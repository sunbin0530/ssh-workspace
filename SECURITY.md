# Security policy

## Trust boundary

This is a local tool for a trusted user and trusted MCP client. Its random loopback HTTP/WebSocket capability grants access to its local sessions. Keep the browser token private. Do not expose the listener through a reverse proxy or to other machines.

The Agent can execute arbitrary commands with the remote account's permissions. The command classifier and deletion summaries are approval assistance, not a sandbox. Encoded commands, aliases, scripts and external APIs cannot be reliably classified by a shell parser. Use least-privileged accounts and server-side access controls.

## Credentials and records

SSH credentials are entered in the local UI and are not returned by MCP. Common inline password/token patterns in Agent commands are rejected before queuing. Use preconfigured remote credential files, environment or a secret manager. Never paste credentials into a prompt.

Known SSH secrets and common credential formats are redacted from model-visible results. Unfinished output lines are held during polling to reduce split-token leakage. Redaction is best effort. The tool cannot recognize every secret, file content or personal record.

Commands and output are held in process memory. Raw terminal bytes are retained in a bounded local terminal buffer and replayed to the authenticated browser. Local processes with the same account, browser extensions, screenshots, remote shell history and bastion audit logs are outside the filter. Closing a process releases its objects but does not guarantee memory zeroization. MCP clients can retain their own conversation and tool histories.

## Target transitions

Each queued Agent command is bound to its target-control revision. Human takeover, a recognized target change, return to the menu, or disconnect invalidates old work and pending approvals. The sender rechecks the revision before each character and the final carriage return. A partial write can leave text in the remote line editor; the user must inspect that terminal before continuing.

Hostname/IP checks and prompt parsing help prevent accidental target confusion. Output from a compromised remote system can be forged. Inner bastion targets are not independently authenticated by this tool.

## Reporting

Before public publication, configure GitHub private vulnerability reporting for the new repository. Send security reports through that channel. Avoid public issues containing credentials, private hostnames, terminal transcripts or reproduction data from real environments.

## Release checks

Run regression tests, inspect the release file list and run dependency audits for the target OS. Windows and macOS dependency resolution can differ. Do not infer macOS support from a successful Windows simulation. The Windows dependency set was audited after upgrading Paramiko to 5.0.1 with no known vulnerabilities reported. See AUDIT.md. A complete penetration test and macOS runtime validation remain outstanding.
