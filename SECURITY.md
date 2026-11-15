<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Reporting a suspected source exposure

Contact a RakuenSoftware repository administrator privately. Do not include
suspected private source or credentials in a public issue, pull request, comment
or attachment. Identify the release/run URL and affected file paths privately.

Administrators should disable the build workflow and revoke its read-only source
credential while investigating. Quarantine affected public artifacts and examine
repository history, run logs and release assets privately. Removing a download
does not revoke copies already obtained. Preserve licence notices on binaries.

Only trusted maintainers may change publication workflows or dispatch builds.
Review changes to the file allowlist, credential permissions, checkout paths,
log handling and artifact paths as changes to the source publication boundary.
