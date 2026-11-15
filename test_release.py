# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from release import SDKRelease


class ReleaseBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commit = 'a' * 40
        pe = bytearray(512)
        pe[:2] = b'MZ'
        struct.pack_into('<I', pe, 0x3c, 128)
        pe[128:132] = b'PE\0\0'
        struct.pack_into('<H', pe, 148, 240)
        struct.pack_into('<H', pe, 152, 0x20b)
        self.pe = bytes(pe)

    def sdk(self, target='linux-x64', extra=None, manifest_extra=None, managed=None):
        platform, arch, extension = SDKRelease.TARGETS[target]
        editor = {'linux-x64': 'editor/Godot_v4.7.2-stable_mono_linux.x86_64', 'windows-x64': 'editor/Godot_v4.7.2-stable_mono_win64.exe', 'macos-universal': 'editor/Godot.app/Contents/MacOS/Godot'}[target]
        native = {'linux-x64': b'\x7fELFfixture', 'windows-x64': self.pe, 'macos-universal': b'\xca\xfe\xba\xbefixture'}[target]
        files = {'WolEngine.props': b'<Project/>', 'GodotApi.props': b'<Project/>', 'native/spatial.gdextension': b'[configuration]',
                 f'native/bin/libspatial.{platform}.template_release.{arch}.{extension}': native,
                 'managed/Debug/WolEngine.dll': managed or self.pe, 'managed/Release/WolEngine.dll': managed or self.pe,
                 editor: native, 'runtime/PublicIdentity.cs': b'\n'}
        files.update(extra or {})
        manifest = {'schema': 1, 'godot': '4.7.2', 'target': target, 'commit': self.commit, 'editor': editor,
                    'release': f'https://github.com/RakuenSoftware/wol-engine-release/releases/tag/runtime-{self.commit}',
                    'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
        manifest.update(manifest_extra or {})
        archive = self.root / f'wol-engine-{self.commit}-{target}.zip'
        with zipfile.ZipFile(archive, 'w') as packed:
            for name, data in files.items(): packed.writestr(name, data)
            packed.writestr('RUNTIME.json', json.dumps(manifest))
        archive.with_suffix('.zip.sha256').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
        return archive

    def test_native_targets_and_empty_identity_stubs(self):
        for target in SDKRelease.TARGETS:
            with self.subTest(target=target):
                SDKRelease.check_sdk(self.sdk(target), self.commit, target)

    def test_source_diagnostics_disguises_and_traversal_are_rejected(self):
        cases = [('runtime/Engine.cs', b'namespace Wol.Engine; public class Secret {}'),
                 ('runtime/hidden.gdshader', b'shader_type spatial;'),
                 ('runtime/Engine.pdb', b'symbols'), ('logs/build.log', b'compiler context'),
                 ('.git/config', b'private repository configuration'), ('../../Engine.cs', b'source'),
                 ('runtime/branding/README.md', b'namespace Wol.Engine;'),
                 ('native/bin/extra.dll', self.pe), ('runtime/Engine.glsl', b'void fragment() {}')]
        for name, data in cases:
            with self.subTest(name=name), self.assertRaises(ValueError):
                SDKRelease.check_sdk(self.sdk(extra={name: data}), self.commit, 'linux-x64')

    def test_embedded_symbols_and_private_source_in_dependency_packages_are_rejected(self):
        pe = bytearray(self.pe) + bytearray(128)
        struct.pack_into('<H', pe, 134, 1)
        struct.pack_into('<II', pe, 152 + 112 + 48, 0x1000, 28)
        struct.pack_into('<IIII', pe, 392 + 8, 128, 0x1000, 128, 512)
        struct.pack_into('<I', pe, 512 + 12, 17)
        with self.assertRaises(ValueError): SDKRelease.check_sdk(self.sdk(managed=bytes(pe)), self.commit, 'linux-x64')
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, 'w') as packed: packed.writestr('Engine.cs', b'namespace Wol.Engine;')
        with self.assertRaises(ValueError):
            SDKRelease.check_sdk(self.sdk(extra={'editor/GodotSharp/Tools/nupkgs/Godot.NET.Sdk.4.7.2.nupkg': nested.getvalue()}), self.commit, 'linux-x64')

    def test_credentials_checksum_and_unexpected_manifest_fields_are_rejected(self):
        credential = b'github_' + b'pat_' + b'x' * 24
        with self.assertRaises(ValueError): SDKRelease.check_sdk(self.sdk(extra={'runtime/branding/README.md': credential}), self.commit, 'linux-x64')
        with self.assertRaises(ValueError): SDKRelease.check_sdk(self.sdk(manifest_extra={'source': 'unexpected'}), self.commit, 'linux-x64')
        archive = self.sdk(); archive.with_suffix('.zip.sha256').write_text('0' * 64 + '  ' + archive.name + '\n')
        with self.assertRaises(ValueError): SDKRelease.check_sdk(archive, self.commit, 'linux-x64')

    def test_known_windows_editor_bridge_requires_a_binary(self):
        name = 'editor/GodotSharp/Tools/GodotTools.OpenVisualStudio'
        SDKRelease.check_sdk(self.sdk('windows-x64', extra={name: b'\x7fELFfixture'}), self.commit, 'windows-x64')
        with self.assertRaises(ValueError):
            SDKRelease.check_sdk(self.sdk('windows-x64', extra={name: b'private text'}), self.commit, 'windows-x64')

    def test_checksum_sidecars_cannot_carry_extra_content(self):
        archive = self.sdk()
        with archive.with_suffix('.zip.sha256').open('a') as stream: stream.write('private diagnostic text')
        with self.assertRaises(ValueError): SDKRelease.check_sdk(archive, self.commit, 'linux-x64')

    def test_release_requests_and_manual_overrides_require_exact_commits(self):
        directory = self.root / '.github'; directory.mkdir()
        request = directory / 'sdk-release.json'
        request.write_text(json.dumps({'engine_commit': self.commit}))
        self.assertEqual(SDKRelease.requested_commit(self.root), self.commit)
        self.assertEqual(SDKRelease.requested_commit(self.root, 'b' * 40), 'b' * 40)
        for data in ({'engine_commit': 'main'}, {'engine_commit': self.commit + '/extra'},
                     {'engine_commit': self.commit.upper()}, {'engine_commit': self.commit, 'command': 'extra'},
                     {'engine_commit': None}, ['unexpected']):
            request.write_text(json.dumps(data))
            with self.subTest(data=data), self.assertRaises(ValueError):
                SDKRelease.requested_commit(self.root)
        for value in ('', 'main', 'a' * 39, 'a' * 40 + '\n'):
            with self.subTest(override=value), self.assertRaises(ValueError):
                SDKRelease.requested_commit(self.root, value)

    def test_release_request_cli_emits_only_github_job_output(self):
        directory = self.root / '.github'; directory.mkdir()
        request = directory / 'sdk-release.json'
        request.write_text(json.dumps({'engine_commit': self.commit, 'attempt': 2}))
        command = [sys.executable, str(Path(__file__).with_name('release.py').resolve()), 'resolve-request', '--root', str(self.root)]
        result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, 'commit=' + self.commit + '\n')
        result = subprocess.run(command + ['--commit', 'b' * 40], cwd=self.root, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, 'commit=' + 'b' * 40 + '\n')
        for attempt in (0, -1, True, '2', 100001):
            request.write_text(json.dumps({'engine_commit': self.commit, 'attempt': attempt}))
            result = subprocess.run(command, cwd=self.root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
            self.assertNotIn('Traceback', result.stderr)

    def test_repository_history_keeps_deleted_source_visible_to_the_audit(self):
        repo = self.root / 'repo'; repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(repo)], check=True)
        subprocess.run(['git', '-C', str(repo), 'config', 'user.name', 'Fixture'], check=True)
        subprocess.run(['git', '-C', str(repo), 'config', 'user.email', 'fixture@example.invalid'], check=True)
        (repo / 'README.md').write_text('Publication automation only.\n')
        subprocess.run(['git', '-C', str(repo), 'add', 'README.md'], check=True)
        subprocess.run(['git', '-C', str(repo), 'commit', '-qm', 'Public fixture'], check=True)
        SDKRelease.check_repository(repo)
        (repo / 'private.cs').write_text('namespace Wol.Engine;\n')
        subprocess.run(['git', '-C', str(repo), 'add', 'private.cs'], check=True)
        subprocess.run(['git', '-C', str(repo), 'commit', '-qm', 'Synthetic forbidden source'], check=True)
        subprocess.run(['git', '-C', str(repo), 'rm', '-q', 'private.cs'], check=True)
        subprocess.run(['git', '-C', str(repo), 'commit', '-qm', 'Remove synthetic source'], check=True)
        with self.assertRaises(ValueError): SDKRelease.check_repository(repo)


if __name__ == '__main__': unittest.main()
