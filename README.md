<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# WoL Engine binary releases

This public repository owns build automation and binary SDK publication. The
engine implementation stays in the private `RakuenSoftware/wol-engine`
repository. Project Vagrant vendors the downloaded SDK archives from this
repository's Releases page.

## Publication boundary

- Public Git history contains only the explicitly allowed automation, tests,
  documentation and licence files. The audit checks all reachable history, so
  deleting a forbidden file in a later commit does not make it acceptable.
- Merging a reviewed change to `.github/sdk-release.json` into `main` starts
  the native release builds. Manual runs on `main` are also available.
  Pull request checks never receive the source credential. Maintainers who can change `main` or
  workflows are trusted with this credential; review those changes accordingly.
- Each fresh GitHub-hosted Linux, Windows and Mac runner temporarily checks out
  an exact private `runtime-<40-character SHA>` tag into a separate sibling
  directory. The tag's resolved commit must match the requested SHA.
- Compiler output goes to a temporary private file. Failure reports contain only fixed automation-owned categories (for example, a missing include or an overload failure), never captured diagnostic text, paths, source lines or log excerpts.
  The workflow removes the source checkout and compiler output before uploading
  anything. There are no build caches, source artifacts or diagnostic uploads.
- The publication audit verifies archive identity, provenance, every file hash,
  platform binary formats and a restricted file inventory. It rejects nonempty
  C# files, loose shaders, implementation source, debug/symbol packages,
  credentials and logs. Checksum files must contain only their exact checksum
  record. Godot dependency packages are also inspected.
- Only approved ZIP archives and SHA-256 records reach the artifact service.
  A separate publishing job has no private source credential and independently
  audits all three platforms before creating a release. Any failed platform or
  audit prevents publication.

SDKs intentionally include empty C# resource identity stubs, engine branding,
Godot scene resources, licence notices and compiled managed/native binaries.
Compiled code can be inspected or decompiled. Shader programs are compiled into
the managed assembly and can also be recovered from it. This boundary prevents
shipping loose implementation source; it does not provide irreversible secrecy
for software that users execute.

## Enable builds

1. Merge the private engine packaging changes that remove loose shader sources
   and support `--release-repository RakuenSoftware/wol-engine-release`.
2. Configure the repository Actions secret `ENGINE_SOURCE_TOKEN` with a
   fine-grained credential granting **Contents: read** only on the private
   `RakuenSoftware/wol-engine` repository. Do not paste credentials into issues,
   workflow inputs, commits or logs. Keep automatic pull request reviews enabled.
3. Merge this repository's reviewed automation to `main`. Create a private
   engine tag `runtime-<full commit SHA>` for the reviewed source to build.
4. Open a PR updating `.github/sdk-release.json` to that exact commit SHA.
   The PR validates the request and publication policy without private source
   access. Merging it into `main` automatically starts all three native builds.
   This repository's initial request selects the already-tagged engine revision
   `8fd3e8780c985721730855396de987e59e268fcf`.
   To retry an unpublished revision through a PR, increment the request's
   optional positive integer `attempt` field (default: 1). Merging that request
   starts a fresh run without moving the source tag.
   Manual **Build and publish binary SDKs** runs on `main` remain available for
   retries, using the same exact commit SHA.
   All three native-host SDK jobs must pass. The release contains three ZIP
   archives and their checksum records; GitHub's automatic source archives
   contain only this public automation repository.
5. Download those release assets and vendor them into Project Vagrant with its
   existing `tools/release.py --vendor-runtime` command.

The first build must use the new packager. Existing SDKs containing loose shader
files are deliberately rejected. Old downloads are not retroactively removed
by this pipeline.

## Verification

```sh
python -m unittest -v test_release
python release.py check-repository
python release.py stage --input downloaded-sdk-assets --output approved-sdk --commit FULL_SHA
```

The automated tests use deliberate miniature fixtures; they do not build SDKs
locally. Real native compilation and binary consumer qualification run in CI.
Expected audit failures report only fixed public rule labels, never rejected
file names or contents. Unexpected parser errors remain generic. PEM detection
requires encoded key material and a matching end marker; a cryptographic format
marker embedded in Godot is not itself a key. If compilation fails, reproduce
in the private repository to inspect diagnostics. Do not add public compiler
logs to troubleshoot a private build.

Automation in this repository is AGPL-3.0-only. SDK components retain their own
licences and required notices; this repository's licence does not relicense them.

The portable core is published only as `portable/{Debug,Release}/WolEngine.Core.dll`
and its reference props. These DLLs use the same PE/debug-directory audit as the
backend. The allowlist grants no permission for core source, symbols, extra
assemblies or build output; the existing source and log exclusions still apply.
