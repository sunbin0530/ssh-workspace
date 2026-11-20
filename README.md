# SSH Workspace

本机 stdio MCP 连接器。人与 Agent 使用同一个 SSH 终端，支持人工登录、OTP、选机、交还 Agent、主机核对和删除审批。

## 安装

需要 Python 3.11+ 和 Tcl/Tk。安装依赖需要能访问 Python 包仓库，终端网页资源已内置。

Windows，在项目目录的 PowerShell 中执行。

```powershell
.\install.ps1
# 可选注册到 Codex
.\install.ps1 -RegisterCodex
```

macOS，在项目目录执行。

```sh
sh install.sh
# 可选注册到 Codex
sh install.sh --register-codex
# 指定包含 Tcl/Tk 的 Python
sh install.sh --python /path/to/python3
```

Codex 注册使用当前用户的配置文件，已有配置会先备份。遇到同名且指向其他目录的条目时，安装器会提示核对后更新。

Claude Code 和 CodeBuddy 也可注册同一个 MCP。Windows 使用 `.venv/Scripts/python.exe`，macOS 使用 `.venv/bin/python`。命令路径和脚本路径都应为绝对路径。

```sh
claude mcp add --scope user --transport stdio ssh_otp -- /absolute/path/to/python /absolute/path/to/mcp_server.py
codebuddy mcp add --scope user ssh_otp -- /absolute/path/to/python /absolute/path/to/mcp_server.py
```

MCP 由客户端启动。调用 `ssh_connect`，首次打开网页后点「新增」创建连接。默认没有预置主机。普通 SSH 选择标准 SSH，兼容的交互式堡垒机选择菜单适配器。核对主机指纹后完成认证，再在终端选机。进入目标主机后点击「交还 Agent」即可。

独立终端可运行 `python universal_server.py --ui`。配置保存在 `~/.ssh-workspace/profiles.json`。迁移旧连接配置时可使用 `--profiles-file /path/to/profiles.json` 显式选择原文件，私钥路径需按本机环境调整。

## Agent 工作流

1. `ssh_sessions` 发现会话，`ssh_status` 检查状态。
2. 交还后先调用 `ssh_verify_host`，再读取 `ssh_result`，核对主机名和 IP。Kubernetes 任务另外检查当前 context。
3. 用 `ssh_submit` 的 `command` 参数提交单行命令。Agent 判断脚本会删除数据时，提供描述目标和影响的 `deletion_summary`。
4. 普通命令直接执行。明确删除或 Agent 标记的删除需要在网页的「待审批命令」中确认。只有 `approval.ready` 为真才表示提示已就绪。
5. 每条任务都读取结果。人工接管、目标变化或断开使旧审批和待执行任务失效。结果未知的命令由用户核实后再继续。

新会话默认开启 Shell 保活，在主机核对成功、终端停在已识别的 Shell 提示符、无任务且处于 Agent 控制时，空闲满 60 秒发送 `:`。可在网页关闭。同一会话重连保留开关和已有历史，重新登录后需重新核对目标。

## 支持范围

客户端支持 Windows 安装流程。macOS 安装脚本已做语法和模拟流程验证，真实 macOS GUI 与 SSH 联调仍待验证。远端自动化面向 Linux 常见 Bash/POSIX 提示符，主机核对使用 `hostname -I`。支持密码、SSH keyboard-interactive、单私钥认证和交互式堡垒机菜单。复杂多因素认证链、SSH Agent、ProxyJump、SFTP 和 Telnet 尚未适配。

多个客户端启动各自独立的 MCP 进程和 SSH 会话。配置文件通过跨进程锁及原子替换保存。浏览器刷新可重新附着，MCP 退出则会断开 SSH。

## 安全

SSH 依赖为 Paramiko 5.0.1，已移除 SHA-1 密钥交换和 RSA/SHA-1 签名支持。仅支持这些旧算法的服务器需要管理员升级配置。私钥加载已适配新版 password 参数。上游说明见 https://www.paramiko.org/changelog.html 。

使用前阅读 [SECURITY.md](SECURITY.md)。Agent 可以在远端账号权限内执行 Shell 命令，应使用受限账号。删除识别是辅助检查，间接操作依赖 Agent 审查。主机名和 IP 属于运行时信息，外层 SSH 通过核对后的指纹验证。

常见明文凭证参数会在提交前被拒绝。优先使用远端预配置的凭证文件或 Secret 管理服务。模型可见输出会按已知凭证和常见格式脱敏，这不构成完整的数据泄漏防护。原始终端内容仅在本机进程及浏览器内存保留，主机及堡垒机仍可能记录审计日志。

## 开发与发布

```sh
python -m unittest discover
python test_universal.py --smoke
python build_release.py
```

Windows/macOS 安装包和 SHA256 摘要生成在 `dist/`，只包含发布白名单文件。测试数据、用户配置、虚拟环境和个人 Git 历史均不进入安装包。源代码使用 MIT 许可证，内置 xterm 组件的许可证在 `web/LICENSE-*`。
