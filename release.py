#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Own the public repository and binary SDK publication boundary."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import zipfile


class SDKRelease:
    TARGETS = {"linux-x64": ("linux", "x86_64", "so"),
               "windows-x64": ("windows", "x86_64", "dll"),
               "macos-universal": ("macos", "universal", "dylib")}
    PUBLIC_FILES = {"LICENSE", "README.md", "SECURITY.md", "AGENTS.md", ".gitignore", "release.py",
                    "test_release.py", ".github/workflows/build.yml", ".github/workflows/audit.yml"}
    FORBIDDEN = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx", ".gd", ".gdshader", ".gdshaderinc",
                 ".glsl", ".hlsl", ".shader", ".pdb", ".snupkg", ".csproj", ".sln", ".map", ".py", ".sh", ".ps1", ".js", ".ts", ".rs", ".log"}
    SOURCE_TEXT = re.compile(rb'(?m)^\s*(?:namespace\s+Wol\.Engine\b|(?:public|internal)\s+(?:(?:partial|sealed|static|abstract)\s+)*(?:class|struct|interface|record)\s+\w+|shader_type\s+\w+\s*;|void\s+(?:vertex|fragment)\s*\(|#include\s*[<"])')
    SECRET_TEXT = re.compile(rb'(?:-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})')

    @classmethod
    def check_repository(cls, root):
        root = Path(root)
        paths = set(subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")) - {""}
        revisions = subprocess.check_output(["git", "rev-list", "--all"], cwd=root).decode().splitlines()
        for revision in revisions:
            paths.update(subprocess.check_output(["git", "ls-tree", "-r", "--name-only", "-z", revision], cwd=root).decode().split("\0"))
        if paths - cls.PUBLIC_FILES - {""}:
            raise ValueError("Repository contains an unapproved path")
        blobs = set()
        for revision in revisions:
            for row in subprocess.check_output(["git", "ls-tree", "-r", revision], cwd=root).splitlines():
                metadata, _ = row.split(b"\t", 1)
                mode, kind, oid = metadata.split()
                if kind != b"blob" or mode not in (b"100644", b"100755"):
                    raise ValueError("Repository contains a symlink or submodule")
                blobs.add(oid.decode())
        for oid in blobs:
            data = subprocess.check_output(["git", "cat-file", "blob", oid], cwd=root)
            if len(data) > 100_000 or cls.SOURCE_TEXT.search(data) or cls.SECRET_TEXT.search(data):
                raise ValueError("Repository content failed the publication policy")
        for name in paths - {""}:
            path = root / name
            if path.exists() and (path.is_symlink() or cls.SOURCE_TEXT.search(path.read_bytes()) or cls.SECRET_TEXT.search(path.read_bytes())):
                raise ValueError("Working tree failed the publication policy")

    @classmethod
    def check_sdk(cls, archive, commit, target):
        if not re.fullmatch(r"[0-9a-f]{40}", commit) or target not in cls.TARGETS:
            raise ValueError("Invalid SDK identity")
        archive = Path(archive)
        if archive.name != f"wol-engine-{commit}-{target}.zip":
            raise ValueError("Unexpected SDK archive name")
        sidecar = archive.with_suffix(".zip.sha256").read_bytes()
        checksum = sidecar[:64].decode("ascii")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum) or sidecar != (checksum + "  " + archive.name + "\n").encode("ascii"):
            raise ValueError("Unexpected checksum sidecar content")
        with archive.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != checksum:
                raise ValueError("SDK archive checksum mismatch")
        native_platform, arch, extension = cls.TARGETS[target]
        required = {"WolEngine.props", "GodotApi.props", "native/spatial.gdextension",
                    f"native/bin/libspatial.{native_platform}.template_release.{arch}.{extension}",
                    "managed/Debug/WolEngine.dll", "managed/Release/WolEngine.dll"}
        editor = {"linux-x64": "editor/Godot_v4.7.2-stable_mono_linux.x86_64",
                  "windows-x64": "editor/Godot_v4.7.2-stable_mono_win64.exe",
                  "macos-universal": "editor/Godot.app/Contents/MacOS/Godot"}[target]
        required.add(editor)
        with zipfile.ZipFile(archive) as packed:
            members = packed.infolist()
            names = [m.filename for m in members]
            if len(names) != len(set(names)) or len(names) > 4000 or sum(m.file_size for m in members) > 4 * 1024**3:
                raise ValueError("Invalid SDK archive structure")
            manifest = json.loads(packed.read("RUNTIME.json"))
            if set(manifest) != {"schema", "target", "godot", "commit", "release", "editor", "files"}:
                raise ValueError("Unexpected SDK manifest fields")
            if manifest.get("schema") != 1 or manifest.get("commit") != commit or manifest.get("target") != target or manifest.get("godot") != "4.7.2":
                raise ValueError("SDK manifest identity mismatch")
            expected_release = f"https://github.com/RakuenSoftware/wol-engine-release/releases/tag/runtime-{commit}"
            if manifest.get("release") != expected_release:
                raise ValueError("SDK release origin mismatch")
            files = manifest["files"]
            if set(names) != set(files) | {"RUNTIME.json"} or not required <= set(files) or manifest.get("editor") != editor:
                raise ValueError("SDK file manifest mismatch")
            for member in members:
                name = member.filename
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name or path.as_posix() != name or member.is_dir() or stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError("Unsafe SDK member")
                if name == "RUNTIME.json":
                    continue
                data = packed.read(member)
                if hashlib.sha256(data).hexdigest() != files[name]:
                    raise ValueError("SDK member checksum mismatch")
                suffix = path.suffix.lower()
                if suffix in cls.FORBIDDEN or cls.SECRET_TEXT.search(data):
                    raise ValueError("Implementation, diagnostics or credentials in SDK")
                allowed = name in required
                allowed |= bool(re.fullmatch(r"\.dependencies/godot-api/api/(Debug|Release)/GodotSharp(?:Editor)?\.dll", name))
                allowed |= bool(re.fullmatch(r"licenses/[A-Za-z0-9_.-]+\.(?:txt|md)", name))
                allowed |= name == "runtime/display/graphics_settings.tscn"
                allowed |= bool(re.fullmatch(r"runtime/branding/(?:wol_icon\.(?:png|svg)|wol_splash\.(?:png|svg)|README\.md)", name))
                allowed |= name.startswith("runtime/") and (name.endswith(".cs") or name.endswith(".cs.uid") or name == "runtime/display/graphics_settings.tscn.uid")
                if name.startswith("editor/"):
                    allowed |= suffix in {".dll", ".exe", ".json", ".nupkg", ".icns", ".car", ".plist", ".strings"}
                    allowed |= name in {"editor/Godot_v4.7.2-stable_mono_linux.x86_64", "editor/Godot.app/Contents/MacOS/Godot", "editor/Godot.app/Contents/PkgInfo", "editor/Godot.app/Contents/CodeResources", "editor/Godot.app/Contents/_CodeSignature/CodeResources"}
                    if suffix == ".nupkg":
                        allowed = bool(re.search(r"/GodotSharp/Tools/nupkgs/(?:GodotSharp(?:Editor)?|Godot\.NET\.Sdk|Godot\.SourceGenerators)\.4\.7\.2\.nupkg$", name))
                if not allowed:
                    raise ValueError("Unapproved SDK file")
                if suffix == ".nupkg":
                    with zipfile.ZipFile(io.BytesIO(data)) as nested:
                        for entry in nested.infolist():
                            inner = PurePosixPath(entry.filename)
                            if inner.is_absolute() or ".." in inner.parts or "\\" in entry.filename or stat.S_ISLNK(entry.external_attr >> 16):
                                raise ValueError("Unsafe dependency package")
                            content = nested.read(entry)
                            if inner.suffix.lower() in {".pdb", ".gdshader", ".gdshaderinc", ".glsl", ".hlsl"} or cls.SECRET_TEXT.search(content) or re.search(rb"namespace\s+Wol\.Engine\b", content):
                                raise ValueError("Private implementation or symbols in dependency package")
                if suffix == ".cs" and data.strip():
                    raise ValueError("Nonempty C# implementation in SDK")
                if suffix in {".dll", ".exe"} and not data.startswith(b"MZ"):
                    raise ValueError("Invalid PE binary")
                if name.startswith("managed/"):
                    # Owned assemblies must not embed portable PDBs or CodeView paths.
                    pe = struct.unpack_from("<I", data, 0x3c)[0]
                    if data[pe:pe + 4] != b"PE\0\0":
                        raise ValueError("Invalid managed PE header")
                    sections = struct.unpack_from("<H", data, pe + 6)[0]
                    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
                    optional = pe + 24
                    magic = struct.unpack_from("<H", data, optional)[0]
                    if magic not in (0x10b, 0x20b):
                        raise ValueError("Unknown managed PE format")
                    directories = optional + (96 if magic == 0x10b else 112)
                    debug_rva, debug_size = struct.unpack_from("<II", data, directories + 6 * 8)
                    if debug_size:
                        debug_offset = None
                        for index in range(sections):
                            section = optional + optional_size + index * 40
                            size, address, raw_size, raw = struct.unpack_from("<IIII", data, section + 8)
                            if address <= debug_rva < address + max(size, raw_size):
                                debug_offset = raw + debug_rva - address
                        if debug_offset is None or debug_size % 28:
                            raise ValueError("Invalid managed debug directory")
                        for offset in range(debug_offset, debug_offset + debug_size, 28):
                            if struct.unpack_from("<I", data, offset + 12)[0] in (2, 17):
                                raise ValueError("Private debug metadata in managed assembly")
                if suffix == ".so" and not data.startswith(b"\x7fELF"):
                    raise ValueError("Invalid ELF binary")
                if suffix == ".dylib" and data[:4] not in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}:
                    raise ValueError("Invalid Mach-O binary")
                if name == editor and target != "windows-x64" and data[:4] not in ({b"\x7fELF"} if target == "linux-x64" else {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}):
                    raise ValueError("Invalid editor binary")
                if name != editor and suffix not in {".dll", ".exe", ".so", ".dylib", ".nupkg", ".png", ".icns", ".car"} and cls.SOURCE_TEXT.search(data):
                    raise ValueError("Implementation text disguised as an SDK resource")
        return archive

    @classmethod
    def stage(cls, source, destination, commit, targets):
        source, destination = Path(source), Path(destination)
        expected = {f"wol-engine-{commit}-{t}.zip{s}" for t in targets for s in ("", ".sha256")}
        if {p.name for p in source.iterdir() if p.is_file() or p.is_symlink()} != expected:
            raise ValueError("Expected only SDK archives and their checksums")
        if any((source / name).is_symlink() for name in expected):
            raise ValueError("SDK input must not be a symlink")
        for target in targets:
            cls.check_sdk(source / f"wol-engine-{commit}-{target}.zip", commit, target)
        if destination.exists():
            raise ValueError("Choose an unused audit staging directory")
        destination.mkdir(parents=True)
        for name in sorted(expected):
            shutil.copyfile(source / name, destination / name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check-repository", "stage"))
    parser.add_argument("--root", default=".")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--target", choices=tuple(SDKRelease.TARGETS))
    args = parser.parse_args()
    try:
        if args.command == "check-repository":
            SDKRelease.check_repository(args.root)
        else:
            SDKRelease.stage(args.input, args.output, args.commit, (args.target,) if args.target else tuple(SDKRelease.TARGETS))
    except Exception:
        print("PUBLICATION_POLICY_FAILED: output withheld; inspect privately.", file=sys.stderr)
        sys.exit(1)
    print("PUBLICATION_POLICY_OK")
