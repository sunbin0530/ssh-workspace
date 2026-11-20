# Initial security hardening — 2026-11-18

## Verification

- 46 regression tests passed in the independent Windows project environment.
- Stdio MCP smoke test passed, including discovery of 10 tools and denial of unauthenticated command execution.
- Windows and macOS release packages built from a source file allowlist with SHA256SUMS.
- Dependency audit ran through pip-audit against requirements.lock. 35 packages were reported for the current Windows environment, with no known vulnerabilities after upgrading Paramiko to 5.0.1.
- Production source, fixtures and packages were checked for the original internal host/address/account defaults.
- No old project Git history or connection profiles were imported.

## Concrete fixes

- New installations have no preset host or username. Examples use documentation addresses.
- Explicit deletion detection now handles sudo/env options, timeout wrappers and common pathlib deletion calls.
- Common inline password/token arguments are blocked before queuing. Known credentials and common output formats are filtered. Incomplete result lines are held across polls.
- Agent jobs carry the current target-control revision. Target invalidation cancels pending approval and jobs. The sender checks the revision before every character and final carriage return.
- Profile reads and writes use an interprocess file lock. Writes use fsync and atomic replacement.
- Dependency versions and distribution hashes are locked. Installers require hashes.
- MIT license and upstream terminal licenses are included.

## Limits

The deletion classifier is not a sandbox, and credential filtering is not complete DLP. The Agent and remote account must be trusted. A command already executed cannot be undone by changing target state. Raw human terminal history stays in local memory and the remote system may keep audit/history records.

macOS installer syntax and shared source have been checked, but real macOS GUI/SSH execution and the new SSH algorithms against legacy bastions have not been verified. CI workflow definitions are included and have not run on GitHub yet. No penetration test has been performed.

The first dependency audit identified the Paramiko RSA/SHA-1 advisory. The upgrade follows the upstream changelog:
https://www.paramiko.org/changelog.html
