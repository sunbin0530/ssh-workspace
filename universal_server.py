"""Multi-profile, multi-session SSH MCP with a loopback-only human terminal."""
import argparse
from dataclasses import asdict, replace
from ipaddress import ip_address
from pathlib import Path
import queue
import re
import socket
import threading
import time
import tkinter as tk
from types import SimpleNamespace
import uuid
import webbrowser

import paramiko
from mcp.server.fastmcp import FastMCP

from bastion_state import MENU_TOKEN, asset_menu_text
from command_policy import deletion_reason
from mcp_server import AgentConsole
from profiles import ProfileStore
from ssh_otp import Console, fingerprint, send_terminal_line
from terminal_buffer import TerminalBuffer
from redaction import redact


HOST_VERIFICATION_COMMAND = 'hostname && hostname -I'
SHELL_KEEPALIVE_INTERVAL = 60
SHELL_KEEPALIVE_INPUT = b':\r'
SHELL_TARGET = re.compile(
    r'(?:^|\n)(?:\[(?P<bracket>[\w.-]+@[\w.-]+) [^\]\n]*\][#$]'
    r'|(?P<plain>[\w.-]+@[\w.-]+):[^\n]*[#$])\s*$', re.ASCII)


class SessionConsole(AgentConsole):
    PROMPT_TIMEOUT = 300
    browser_handles_bastion_auth = True
    terminal_type = 'xterm-256color'

    def __init__(self, profile, manager):
        self.profile = profile
        self.manager = manager
        self.terminal = TerminalBuffer()
        self.terminal_dimensions = (140, 40)
        self.connection_attempt = 1
        self.previous_results = {}
        self.target_hint = None
        self.verified_host = None
        self.verification_job = None
        self.shell_keepalive = True
        self.control_revision = 0
        self.controller = None
        self.prompt_lock = threading.Lock()
        self.browser_prompt = None
        args = SimpleNamespace(host=profile.host, port=profile.port, user=profile.username,
                               fingerprint=profile.fingerprint, adapter=profile.adapter, command_file=None)
        super().__init__(args, manager.root)
        self.auth_stage = 'connecting'
        self.root.title(f'SSH 认证 / 审批 — {profile.name}')

    def prompt_is_live(self):
        transport = getattr(self, 'transport', None)
        channel = getattr(self, 'channel', None)
        return (not self.stop.is_set() and (transport is None or transport.is_active())
                and (channel is None or not channel.closed))

    def request_prompt(self, kind, title, content, timeout=PROMPT_TIMEOUT):
        request = {'id': uuid.uuid4().hex, 'kind': kind, 'title': title, 'content': content,
                   'done': threading.Event(), 'answer': None, 'deadline': time.monotonic() + timeout}
        with self.prompt_lock:
            if self.browser_prompt or not self.prompt_is_live():
                return None
            self.browser_prompt = request
        try:
            while self.prompt_is_live() and time.monotonic() < request['deadline']:
                if request['done'].wait(.1):
                    return request['answer'] if self.prompt_is_live() else None
            return None
        finally:
            with self.prompt_lock:
                self.browser_prompt = None

    def prompt_pending(self, request):
        return (request and not request['done'].is_set()
                and time.monotonic() < request['deadline'] and self.prompt_is_live())

    def prompt_view(self):
        with self.prompt_lock:
            request = self.browser_prompt
            if self.prompt_pending(request):
                return {key: request[key] for key in ('id', 'kind', 'title', 'content')}

    def answer_prompt(self, prompt_id, approved, value):
        with self.prompt_lock:
            request = self.browser_prompt
            if not self.prompt_pending(request) or request['id'] != prompt_id:
                raise ValueError('此提示已结束，请查看页面当前状态。')
            if approved and request['kind'] == 'secret' and not value:
                raise ValueError('请输入凭证。')
            request['answer'] = (value if request['kind'] in ('secret', 'share') else True) if approved else None
            request['done'].set()

    def ask_secret(self, title, prompt):
        answer = self.request_prompt('secret', title, prompt)
        if answer is None:
            raise RuntimeError('认证已取消或超时')
        self.secrets.append(answer)
        return answer

    def review_command(self, command):
        return self.request_prompt('approval', '确认远端命令', redact(command, self.secrets)) is True

    def invalidate_target(self):
        """Caller holds the manager lock. Invalidate queued work and open approvals."""
        self.target_ready = False
        self.verified_host = None
        self.verification_job = None
        self.control_revision += 1
        self.jobs.uncertain()
        with self.prompt_lock:
            request = self.browser_prompt
            if request and request['kind'] == 'approval':
                request['answer'] = None
                request['done'].set()

    def share_menu(self):
        if self.auth_stage != 'submitted' or self.human_active or self.stop.is_set():
            return
        content = self.bastion.candidate
        for secret in self.secrets:
            if secret:
                content = content.replace(secret, '[REDACTED]')
        reviewed = self.request_prompt('share', '确认共享资产菜单', content)
        if reviewed is not None and self.auth_stage == 'submitted' and not self.human_active and not self.stop.is_set():
            self.bastion.grant(reviewed)

    def can_confirm_target(self, revision):
        return (revision == self.control_revision and not self.human_active and self.auth_stage == 'shell'
                and self.channel and not self.channel.closed and not self.stop.is_set())

    def queue_target_confirmation(self, revision):
        with self.manager.lock:
            if type(revision) is not int or not self.can_confirm_target(revision):
                raise ValueError('目标状态已变化，请刷新状态后重新确认。')
            with self.jobs.lock:
                key = self.jobs.active
                if key and self.jobs.items[key]['status'] != 'disconnected_outcome_unknown':
                    raise ValueError('请等待当前 Agent 任务结束，再确认目标。')
            self.target_ready = False
            self.events.put(('mcp_confirm', revision))

    def confirm_target(self, revision=None):
        if revision is None:
            return
        with self.manager.lock:
            if not self.can_confirm_target(revision):
                return
        key = self.jobs.active
        if key:
            job = self.jobs.read(key)
            if job['status'] == 'disconnected_outcome_unknown':
                checked = self.request_prompt('confirm', '核实接管前任务',
                    '接管前任务结果未知。请先核实远端操作已结束、终端已回到目标 Shell。\n'
                    '确认后保留该任务的未知结果记录，仅允许新的命令。')
                if not checked:
                    return
        with self.manager.lock:
            if not self.can_confirm_target(revision):
                return
            with self.jobs.lock:
                if key and self.jobs.active == key and self.jobs.items[key]['status'] == 'disconnected_outcome_unknown':
                    self.jobs.items[key]['status'] = 'outcome_unknown_reviewed_by_user'
                    self.jobs.active = None
            self.verified_host = None
            self.verification_job = None
            self.control_revision += 1
            self.target_ready = True

    def verify_host_key(self, key):
        actual = fingerprint(key)
        if self.args.fingerprint:
            return super().verify_host_key(key)
        approved = self.request_prompt('confirm', '核对 SSH 主机指纹',
            f'{self.profile.username}@{self.profile.host}:{self.profile.port}\n\n{actual}\n\n'
            '与管理员或可信记录核对一致后，确认保存此指纹。')
        if not approved or self.stop.is_set():
            raise RuntimeError('Host key was not approved')
        self.profile = replace(self.profile, fingerprint=actual)
        self.manager.profiles.save(self.profile)
        self.args.fingerprint = actual

    def authenticate(self, transport):
        self.auth_stage = 'ssh_authenticating'
        # Paramiko waits for keyboard-interactive callbacks within this deadline.
        transport.auth_timeout = self.PROMPT_TIMEOUT * 2 + 30
        if not self.profile.private_key_path:
            return super().authenticate(transport)
        key_path = Path(self.profile.private_key_path).expanduser()
        try:
            key = paramiko.PKey.from_path(key_path)
        except (paramiko.PasswordRequiredException, TypeError):
            phrase = self.ask_secret('SSH 私钥口令', f'请输入私钥口令：{key_path.name}')
            key = paramiko.PKey.from_path(key_path, password=phrase.encode())
        transport.auth_publickey(self.profile.username, key)
        if not transport.is_authenticated():
            raise RuntimeError('Private-key authentication was not completed')

    def on_terminal_data(self, data):
        self.terminal.append(data)

    def resize_terminal(self, cols, rows):
        with self.manager.lock:
            self.terminal_dimensions = (cols, rows)
            self.on_terminal_opened()

    def on_terminal_opened(self):
        with self.manager.lock:
            if self.channel and not self.channel.closed and not self.stop.is_set():
                cols, rows = self.terminal_dimensions
                self.channel.resize_pty(width=cols, height=rows)

    def on_terminal_idle(self, tail, idle_seconds):
        if not self.shell_keepalive or idle_seconds < SHELL_KEEPALIVE_INTERVAL:
            return False
        match = SHELL_TARGET.search(tail)
        if not match or (match.group('bracket') or match.group('plain')) != self.target_hint:
            return False
        with self.manager.lock:
            channel = self.channel
            if (not self.shell_keepalive or self.auth_stage != 'shell' or not self.target_ready
                    or not self.verified_host or self.human_active or self.controller is not None
                    or self.jobs.active or self.navigation_pending or self.stop.is_set()
                    or not channel or channel.closed or self.prompt_view()):
                return False
            # Do not wait behind a sender. The control lock prevents a takeover
            # or queued Agent job from starting while these two bytes are sent.
            if not self.send_lock.acquire(blocking=False):
                return False
            try:
                if channel.recv_ready() or not channel.send_ready():
                    return False
                if channel.send(SHELL_KEEPALIVE_INPUT) != len(SHELL_KEEPALIVE_INPUT):
                    raise OSError('Incomplete shell keepalive write')
            except (OSError, EOFError):
                self.shell_keepalive = False
                self.target_ready = False
                self.control_revision += 1
                self.terminal.append('\r\n[SSH Workspace] Shell 保活发送失败，请检查终端并重新确认目标。\r\n'.encode())
            finally:
                self.send_lock.release()
        return True

    def read_job(self, job_id):
        if job_id in self.previous_results:
            return self.previous_results[job_id]
        result = self.jobs.read(job_id, self.secrets)
        if result['status'] == 'awaiting_user_confirmation':
            prompt = self.prompt_view()
            result['approval'] = {
                'ready': bool(prompt and prompt['kind'] == 'approval'),
                'location': 'SSH Workspace browser, 待审批命令 button',
                'reason': redact(self.jobs.items[job_id]['approval_reason'], self.secrets),
                'action': 'Click 确认执行 or 取消 in SSH Workspace. Do not type an approval into chat.',
            }
        if (self.target_ready and not self.stop.is_set()
                and self.verification_job == (job_id, self.control_revision)
                and result['status'] == 'completed' and result['exit_code'] == 0):
            lines = result['output'].strip().splitlines()
            if len(lines) == 2 and re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', lines[0]):
                try:
                    addresses = [str(ip_address(value)) for value in lines[1].split()]
                except ValueError:
                    addresses = []
                if addresses:
                    self.verified_host = {'hostname': lines[0], 'addresses': addresses}
        return result

    def on_terminal_text(self, clean, tail, previous_stage):
        if self.auth_stage == 'shell' and self.adapter.post_login_mfa and (menu := asset_menu_text(tail)):
            with self.manager.lock:
                self.invalidate_target()
                self.target_hint = None
                self.bastion.reset()
                self.bastion.feed(menu, True)
                self.auth_stage = 'submitted'
            super().on_terminal_text(clean, tail, previous_stage)
            return
        if (match := SHELL_TARGET.search(tail)) and (self.auth_stage == 'shell' or self.human_active):
            hint = match.group('bracket') or match.group('plain')
            if len(hint) <= 253 and hint != self.target_hint:
                with self.manager.lock:
                    if self.target_hint is not None:
                        self.invalidate_target()
                    self.target_hint = hint
        # Admit only post-authentication output to the shareable menu. The
        # transition chunk can contain terminal echo from the login dialogue.
        if self.auth_stage == 'submitted':
            if previous_stage != 'submitted':
                marker = tail.rfind('操作命令')
                if marker >= 0:
                    self.bastion.feed(tail[marker:], True)
            else:
                self.bastion.feed(clean, True)
        elif self.auth_stage == 'shell':
            self.bastion.feed(clean, False)
        if self.target_ready:
            self.jobs.feed(clean)
        super().on_terminal_text(clean, tail, previous_stage)

    def execute_job(self, key, wrapped):
        def allowed():
            return (self.auth_stage == 'shell' and self.target_ready and not self.human_active
                    and not self.stop.is_set() and self.jobs.active == key
                    and self.jobs.items[key].get('target_revision') == self.control_revision
                    and self.jobs.items[key]['status'] == 'running')

        try:
            with self.send_lock:
                channel = self.channel
                if channel is None or channel.closed or not allowed():
                    raise RuntimeError('Target Shell is no longer available')
                send_terminal_line(channel, wrapped, self.stop, pause=.005,
                                   abort_if=lambda: not allowed(), guard=self.manager.lock)
        except Exception:
            with self.manager.lock:
                self.jobs.uncertain(key)
                if self.jobs.active == key:
                    self.target_ready = False

    def append(self, text):
        Console.append(self, redact(text, self.secrets))

    def disconnect(self):
        with self.manager.lock:
            self.invalidate_target()
            self.stop.set()
            self.controller = None
            self.human_active = False
        super().disconnect()

    def handle_control_event(self, kind, value):
        if kind == 'mcp_connect':
            self.connect()
            return False
        if kind == 'mcp_human':
            self.status.set('人工接管中，Agent 输入已暂停' if self.human_active else '已交还 Agent，等待核对主机')
            return False
        if kind in ('mcp_confirm', 'mcp_share', 'mcp_disconnect', 'mcp_submit'):
            def handle():
                if kind == 'mcp_confirm':
                    self.confirm_target(value)
                elif kind == 'mcp_share':
                    self.share_menu()
                elif kind == 'mcp_disconnect':
                    if not self.jobs.active or self.request_prompt('confirm', '断开会话', '当前任务尚未结束，断开可能影响前台进程。'):
                        self.disconnect()
                elif kind == 'mcp_submit':
                    self.submit_queued_job(*value)
                else:
                    super(SessionConsole, self).handle_control_event(kind, value)
            threading.Thread(target=handle, daemon=True).start()
            return False
        return super().handle_control_event(kind, value)

    def submit_queued_job(self, key, expires):
        def current():
            return (self.target_ready and self.auth_stage == 'shell' and not self.human_active
                    and not self.stop.is_set() and time.monotonic() <= expires
                    and job.get('target_revision') == self.control_revision)

        with self.manager.lock:
            job = self.jobs.items[key]
            if not current() or job['status'] != 'queued':
                self.jobs.approve(key, False)
                return
            reason = job['approval_reason']
            if reason:
                job['status'] = 'awaiting_user_confirmation'
        approved = self.review_command(reason + '\n\n' + job['command']) if reason else True
        with self.manager.lock:
            wrapped = self.jobs.approve(key, approved and current())
        if wrapped:
            self.execute_job(key, wrapped)


class Manager:
    def __init__(self, profiles_path):
        self.root = tk.Tk()
        self.root.withdraw()
        self.profiles = ProfileStore(profiles_path)
        self.sessions = {}
        self.lock = threading.RLock()
        self.requests = queue.Queue()
        self.browser_url = None
        self.browser_seen = None
        self.root.after(50, self.pump)

    def pump(self):
        try:
            while True:
                task = self.requests.get_nowait()
                if task.get('cancelled'):
                    continue
                try:
                    task['value'] = task['fn']()
                except Exception as error:
                    task['error'] = str(error)
                finally:
                    task['done'].set()
        except queue.Empty:
            pass
        self.root.after(50, self.pump)

    def local(self, fn):
        task = {'fn': fn, 'done': threading.Event()}
        self.requests.put(task)
        if not task['done'].wait(10):
            task['cancelled'] = True
            raise RuntimeError('Local UI is busy; inspect the local window before retrying')
        if 'error' in task:
            raise ValueError(task['error'])
        return task.get('value')

    def open_ui(self):
        with self.lock:
            if self.browser_seen is not None and time.monotonic() - self.browser_seen < 60:
                return 'local_browser_already_open'
            if self.browser_url and webbrowser.open(self.browser_url):
                self.browser_seen = time.monotonic()
                return 'local_browser_requested'
            return 'local_browser_unavailable'

    def browser_heartbeat(self):
        with self.lock:
            self.browser_seen = time.monotonic()

    def prompts(self):
        with self.lock:
            return [dict(prompt, session_id=key, name=console.profile.name)
                    for key, console in self.sessions.items() if (prompt := console.prompt_view())]

    def connect(self, profile_id):
        profile = self.profiles.get(profile_id)

        def create():
            key = uuid.uuid4().hex[:12]
            console = SessionConsole(profile, self)
            with self.lock:
                self.sessions[key] = console
            console.events.put(('mcp_connect', None))
            if self.browser_seen is None:
                self.open_ui()
            return self.connection_request(key, console)

        return self.local(create)

    def reconnect(self, key):
        def restart():
            with self.lock:
                old = self.get(key)
                if old.closed or old.auth_stage != 'disconnected' or not old.stop.is_set():
                    raise ValueError('只能重新连接已断开的会话。')
                console = SessionConsole(old.profile, self)
                console.connection_attempt = old.connection_attempt + 1
                console.terminal_dimensions = old.terminal_dimensions
                console.shell_keepalive = old.shell_keepalive
                console.terminal.append(old.terminal.since(0)[1])
                console.terminal.append(b'\r\n\x1b[0m[SSH Workspace: new SSH connection]\r\n')
                console.previous_results = old.previous_results.copy()
                with old.jobs.lock:
                    for job_id in old.jobs.items:
                        console.previous_results[job_id] = old.jobs.read(job_id, old.secrets)
                old.close()
                self.sessions[key] = console
                self.select_session(key)
                console.events.put(('mcp_connect', None))
                return self.connection_request(key, console)
        return self.local(restart)

    @staticmethod
    def connection_request(key, console):
        return {'session_id': key, 'profile_id': console.profile.id,
                'connection_attempt': console.connection_attempt, 'status': 'local_authentication_requested'}

    def get(self, session_id=None):
        with self.lock:
            if not session_id:
                if len(self.sessions) != 1:
                    raise ValueError('Specify session_id; there must be exactly one session to omit it')
                return next(iter(self.sessions.values()))
            if session_id not in self.sessions:
                raise ValueError('Unknown session_id')
            return self.sessions[session_id]

    def statuses(self, browser=False):
        with self.lock:
            return [self.status(key, browser=browser) for key in reversed(self.sessions)]

    def select_session(self, key):
        with self.lock:
            if key not in self.sessions:
                raise ValueError('会话不存在。')
            self.sessions[key] = self.sessions.pop(key)

    def mark_session_used(self, console):
        with self.lock:
            key = next((key for key, value in self.sessions.items() if value is console), None)
            if key is not None:
                self.select_session(key)

    def set_shell_keepalive(self, key, enabled):
        if type(enabled) is not bool:
            raise ValueError('Shell 保活开关必须为布尔值。')
        with self.lock:
            console = self.get(key)
            if enabled and (console.auth_stage != 'shell' or not console.target_ready
                            or not console.verified_host or console.stop.is_set()
                            or not console.channel or console.channel.closed):
                raise ValueError('请先确认目标 Shell 并核对主机，再开启 Shell 保活。')
            console.shell_keepalive = enabled

    def remove_session(self, key):
        def remove():
            with self.lock:
                if key not in self.sessions:
                    raise ValueError('会话不存在。')
                console = self.sessions[key]
                if console.auth_stage != 'disconnected' or not console.stop.is_set():
                    raise ValueError('请先断开此会话，再删除记录。')
                console.close()
                del self.sessions[key]
        return self.local(remove)

    def status(self, key, browser=False):
        console = self.get(key)
        confirmed = console.target_ready and not console.stop.is_set()
        verified_host = console.verified_host if confirmed else None
        return {'session_id': key, 'profile_id': console.profile.id, 'name': console.profile.name,
                'connection_attempt': console.connection_attempt,
                'host': console.profile.host, 'username': console.profile.username,
                'connected': bool(console.transport and console.transport.is_authenticated() and not console.stop.is_set()),
                'stage': console.auth_stage, 'target_confirmed': confirmed, 'verified_host': verified_host,
                **({'target_revision': console.control_revision} if browser else {}),
                'verification_command': HOST_VERIFICATION_COMMAND if confirmed and not verified_host else None,
                'shell_keepalive': console.shell_keepalive,
                'human_active': console.human_active, 'asset_menu_shared': console.bastion.shared,
                'active_job_id': console.jobs.active, 'navigation': console.navigation, 'window_closed': console.closed}


def build_server(manager):
    server = FastMCP(
        'ssh-otp', log_level='WARNING',
        instructions=(
            'Use ssh_sessions to discover session IDs. After the user confirms the target Shell, '
            'call ssh_verify_host and then ssh_result before other remote commands. '
            'For remote Linux commands use ssh_submit with a single-line command argument, not data. '
            'Do not run those commands in the local PowerShell or Bash. '
            'Inspect script effects yourself and use deletion_summary for concrete deletion operations. '
            'Poll ssh_result; queued does not mean an approval prompt is ready. '
            'The user completes authentication and any deletion approval in SSH Workspace.'
        ),
    )

    @server.tool()
    def ssh_profiles() -> list[dict]:
        """List non-secret saved connection profiles. User adds/edits profiles locally; never pass credentials in tools."""
        return [asdict(item) for item in manager.profiles.list()]

    @server.tool()
    def ssh_connect(profile_id: str | None = None) -> dict:
        """Create a persistent SSH session from a saved profile and open the human terminal. User completes local password/OTP/key/trust prompts. Returns session_id, not authentication success."""
        if profile_id is None:
            profiles = manager.profiles.list()
            if not profiles:
                return {'status': 'profile_required', 'ui': manager.local(manager.open_ui)}
            if len(profiles) != 1:
                raise ValueError('Call ssh_profiles and specify a profile_id')
            profile_id = profiles[0].id
        return manager.connect(profile_id)

    @server.tool()
    def ssh_open_ui() -> dict:
        """Open the local human terminal UI without exposing its browser-only access token to the model."""
        return {'status': manager.local(manager.open_ui)}

    @server.tool()
    def ssh_sessions() -> list[dict]:
        """List session identities and stages, without terminal/login transcripts."""
        return manager.statuses()

    @server.tool()
    def ssh_status(session_id: str | None = None) -> dict:
        """Read the current state and whether to use ssh_verify_host. Discover the session ID with ssh_sessions before calling this tool."""
        with manager.lock:
            console = manager.get(session_id)
            key = next(key for key, value in manager.sessions.items() if value is console)
            return manager.status(key)

    def submit_remote_command(command: str, session_id: str | None, deletion_summary: str | None = None) -> dict:
        if deletion_summary is not None and (not deletion_summary.strip() or len(deletion_summary) > 2000):
            raise ValueError('deletion_summary must describe the concrete deletion and its affected targets')
        with manager.lock:
            console = manager.get(session_id)
            if console.profile.adapter == 'company-bastion' and console.auth_stage == 'submitted':
                raise ValueError('The target Shell is no longer active. Select the target from the bastion menu, then confirm and verify the host again.')
            if console.human_active or not console.target_ready or console.stop.is_set() or console.navigation_pending:
                raise ValueError('User must release human control and confirm the target Shell locally')
            verifying = console.verified_host is None
            if verifying and command.strip() != HOST_VERIFICATION_COMMAND:
                raise ValueError('First verify the current host with ssh_verify_host, then read its ssh_result')
            key = console.jobs.submit(command, deletion_summary)
            console.jobs.items[key]['target_revision'] = console.control_revision
            requires_confirmation = bool(console.jobs.items[key]['approval_reason'])
            if verifying:
                console.verification_job = (key, console.control_revision)
            manager.mark_session_used(console)
            console.events.put(('mcp_submit', (key, time.monotonic() + 300)))
        return {'job_id': key, 'status': 'queued', 'requires_confirmation': requires_confirmation,
                'next_action': 'Poll ssh_result. queued is not an approval request; await an actual approval.ready response before directing the user to SSH Workspace.'}

    @server.tool()
    def ssh_verify_host(session_id: str) -> dict:
        """Queue a fixed read-only hostname and IP check on the user-confirmed remote Shell. Pass only session_id. Read the returned job_id with ssh_result before running other commands."""
        return submit_remote_command(HOST_VERIFICATION_COMMAND, session_id)

    @server.tool()
    def ssh_submit(command: str, session_id: str | None = None, deletion_summary: str | None = None) -> dict:
        """Queue a single-line remote command via command, not data. Agent must inspect scripts and indirect effects first. If they delete resources or data, supply deletion_summary describing targets and impact to request approval. Do not request approval merely for shell substitution or script execution. Explicit deletion is also detected locally. Poll ssh_result until done; direct the user to SSH Workspace only when approval.ready is true."""
        return submit_remote_command(command, session_id, deletion_summary)

    @server.tool()
    def ssh_result(job_id: str, session_id: str | None = None) -> dict:
        """Read only marked job output/exit status, not login or human-terminal output. Unknown/running outcomes must not be retried blindly."""
        with manager.lock:
            return manager.get(session_id).read_job(job_id)

    @server.tool()
    def ssh_bastion_view(session_id: str | None = None) -> dict:
        """Read the company adapter's locally approved asset-menu transcript only."""
        console = manager.get(session_id)
        if console.profile.adapter != 'company-bastion':
            raise ValueError('This profile uses standard SSH, not the company menu adapter')
        return console.bastion.read(console.secrets)

    @server.tool()
    def ssh_bastion_send(menu_input: str, session_id: str | None = None) -> dict:
        """Send a single observed asset-menu token. No credentials/shell syntax. User must first share the menu; blocked in human mode or a Shell."""
        console = manager.get(session_id)
        if not MENU_TOKEN.fullmatch(menu_input):
            raise ValueError('Expected one safe menu token')
        if console.profile.adapter != 'company-bastion' or console.human_active or not console.bastion.shared or console.auth_stage != 'submitted' or console.stop.is_set():
            raise ValueError('Asset navigation is not authorized or applicable')
        if console.jobs.active or console.navigation_pending:
            raise ValueError('Another operation is pending')
        console.navigation_pending = True
        manager.mark_session_used(console)
        console.navigation = {'status': 'queued', 'input': menu_input}
        console.events.put(('mcp_bastion', (menu_input, time.monotonic() + 300)))
        return console.navigation

    return server


def main():
    import uvicorn
    from terminal_web import make_app

    parser = argparse.ArgumentParser()
    parser.add_argument('--profiles-file', type=Path, default=Path.home() / '.ssh-workspace/profiles.json')
    parser.add_argument('--ui', action='store_true', help='Open the standalone connection manager without an MCP client')
    args = parser.parse_args()
    manager = Manager(args.profiles_file)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(32)
    port = listener.getsockname()[1]
    app, token = make_app(manager, port)
    manager.browser_url = f'http://127.0.0.1:{port}/#{token}'
    http = uvicorn.Server(uvicorn.Config(app, log_level='error', access_log=False, proxy_headers=False))
    threading.Thread(target=lambda: http.run(sockets=[listener]), daemon=True).start()
    server = build_server(manager)

    def serve():
        try:
            server.run(transport='stdio')
        finally:
            http.should_exit = True
            manager.requests.put({'fn': manager.root.quit, 'done': threading.Event()})

    if args.ui:
        manager.root.after(800, manager.open_ui)
    else:
        threading.Thread(target=serve, daemon=True).start()
    try:
        manager.root.mainloop()
    finally:
        with manager.lock:
            for console in manager.sessions.values():
                console.disconnect()
        http.should_exit = True
        listener.close()


if __name__ == '__main__':
    main()
