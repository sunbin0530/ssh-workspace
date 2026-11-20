---
name: ssh-workspace
description: Operate remote Linux hosts through the local SSH Workspace stdio MCP, shared human terminal, target verification and concrete deletion approvals.
---

# SSH Workspace

Use the registered ssh_otp MCP server. The browser and Agent share the same SSH channel.

1. Discover saved profiles and sessions with ssh_profiles and ssh_sessions. New installations start with no profiles. Call ssh_connect to open the local browser. The human configures the host, verifies its fingerprint, logs in and selects a target.
2. The human clicks 交还 Agent in a target Shell. Use ssh_status, then ssh_verify_host and ssh_result. Check the hostname and IP before other commands. For Kubernetes, also check kubectl config current-context.
3. Submit a single-line Linux command through ssh_submit(command, session_id). Never send remote commands to local PowerShell/Bash. Inspect scripts and indirect effects yourself. If deletion is involved, provide deletion_summary with the concrete targets and impact.
4. Poll ssh_result until completion. Only approval.ready=true means the local browser has a live approval. Use ssh_open_ui if it is not visible. The user approves via 待审批命令, then 确认执行 or 取消. Do not ask the user to decide whether an ordinary script might indirectly delete.
5. Any human takeover or target change invalidates queued work and approvals. Recheck ssh_status and the host after the next handoff. Unknown command outcomes require human inspection, never automatic replay.

Credentials belong in the local authentication UI or a remote secret manager/config file. Do not put passwords or API tokens in commands or chat. Redaction is best effort. Use least-privileged remote accounts.

For menu navigation, ssh_bastion_view/ssh_bastion_send require a locally shared asset menu. Follow the actual observed menu. Some menus handle s as an immediate key; wait for the search prompt before sending the keyword.

Runtime configuration is in ~/.ssh-workspace/profiles.json. Existing installations can explicitly choose an old profile file via --profiles-file. Windows uses .venv/Scripts/python.exe, macOS uses .venv/bin/python. Both run mcp_server.py through stdio. Standalone UI uses universal_server.py --ui. Different client processes have separate SSH sessions.

Shell keepalive defaults to on. It sends : after 60 idle seconds only at a verified Shell prompt without an active job or human control. The user can disable it in the browser.

Never delete remote data or resources without concrete local user approval. The classifier is a guard, not a sandbox. Read SECURITY.md for the full trust boundary.
