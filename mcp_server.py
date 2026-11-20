"""stdio MCP and Tk share one process. No HTTP port or credential IPC."""
import argparse
import logging
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext

from mcp.server.fastmcp import FastMCP

from job_state import Jobs
from bastion_state import BastionView, MENU_TOKEN, is_immediate_menu_key
from command_policy import deletion_reason
from dialog_layout import review_layout
from ssh_otp import Console


class AgentConsole(Console):
    def __init__(self, args, parent=None):
        super().__init__(args, parent)
        self.root.title('SSH OTP MCP v7 — 确认窗口布局修复')
        self.commands = ''
        self.jobs = Jobs()
        self.bastion = BastionView()
        self.navigation = {'status': 'idle'}
        self.navigation_pending = False
        self.target_ready = False
        self.opening = False
        self.closed = False
        self.connect_button.configure(text='连接堡垒机')
        tk.Button(self.root, text='认证已完成：共享资产菜单，允许 Agent 检索 / 选机',
                  command=self.share_menu).pack(fill='x')
        tk.Button(self.root, text='我已进入目标 Linux Shell，允许接收 Agent 命令',
                  command=self.confirm_target).pack(fill='x')
        self.root.withdraw()

    def confirm_target(self):
        if self.auth_stage != 'shell' or not self.channel or self.channel.closed:
            messagebox.showinfo('尚未进入 Shell', '请先完成 OTP 和资产选择，等待出现 Linux Shell 提示符。')
            return
        if messagebox.askokcancel('确认目标主机', '请核对窗口中的目标主机。确认已进入期望的 Linux Shell？\n一般命令直接执行；删除或可能间接删除的命令单独确认。'):
            self.target_ready = True
            self.bastion.shared = False
            self.status.set('目标 Shell 已由用户确认，等待 Agent 命令')

    def share_menu(self):
        if self.auth_stage != 'submitted' or not self.channel or self.channel.closed:
            messagebox.showinfo('尚未进入资产菜单', '请先完成 OTP，确认窗口已显示堡垒机资产菜单。若已进入 Shell，请直接确认目标。')
            return
        content = self.bastion.candidate
        for secret in self.secrets:
            if secret:
                content = content.replace(secret, '[REDACTED]')
        dialog, preview, actions = review_layout(self.root,
            '确认共享资产菜单（可编辑移除敏感内容）',
            '仅在认证成功且显示资产菜单后批准。以下文本及之后的菜单响应将提供给 Agent。', content, editable=True)

        def accept():
            if self.auth_stage != 'submitted' or self.stop.is_set():
                dialog.destroy()
                return
            self.bastion.grant(preview.get('1.0', 'end-1c'))
            self.status.set('资产菜单已共享，Agent 可检索 / 选机；进入 Shell 后需确认目标')
            dialog.destroy()

        tk.Button(actions, text='取消', command=dialog.destroy).grid(row=0, column=0, sticky='w')
        tk.Button(actions, text='确认认证完成并共享菜单', command=accept).grid(row=0, column=1, sticky='e')
        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

    def connect(self):
        if self.opening:
            return
        if self.jobs.active:
            messagebox.showinfo('任务状态未结清', '请先读取任务结果；不要在结果未知时重新执行。需要新会话时重启 MCP 连接器。')
            return
        self.target_ready = False
        self.bastion.reset()
        self.opening = True
        self.stop.clear()
        self.connect_button.configure(state='disabled')
        threading.Thread(target=self.run, daemon=True).start()

    def append(self, text):
        self.bastion.feed(text, self.auth_stage == 'submitted' and not self.target_ready)
        # Only a submitted, user-approved job between random markers enters model-visible storage.
        if self.target_ready:
            self.jobs.feed(text)
        super().append(text)

    def send_line(self, text):
        if self.auth_stage == 'submitted' and is_immediate_menu_key(text, self.bastion.tail):
            with self.send_lock:
                if not self.channel or self.stop.is_set():
                    raise RuntimeError('Not connected')
                self.channel.sendall(b's')
            return
        super().send_line(text)

    def send_manual(self):
        if self.jobs.active or self.navigation_pending:
            messagebox.showinfo('Agent 任务处理中', '请等待当前任务完成，避免混入命令或结果。')
            return
        # Local intervention invalidates the target assertion (user may hop to a different host).
        self.target_ready = False
        super().send_manual()

    def disconnect(self):
        self.target_ready = False
        self.opening = False
        self.jobs.uncertain()
        self.bastion.reset()
        if self.navigation_pending:
            self.navigation = {'status': 'disconnected_outcome_unknown'}
            self.navigation_pending = False
        super().disconnect()

    def close(self):
        self.closed = True
        super().close()

    def execute_job(self, key, wrapped):
        try:
            self.send_line(wrapped)
        except Exception:
            self.jobs.uncertain(key)
            self.target_ready = False
            self.events.put(('status', '发送中断，结果未知；请检查远端，不自动重试'))

    def review_command(self, command):
        dialog, preview, actions = review_layout(self.root,
            '确认远端命令：删除操作需确认',
            '请核对目标主机与完整命令。以下命令尚未执行；Esc 或右上角 × 均表示取消。', command)
        answer = [False]

        def accept():
            answer[0] = True
            dialog.destroy()

        tk.Button(actions, text='取消，不执行', command=dialog.destroy).grid(row=0, column=0, sticky='w')
        tk.Button(actions, text='确认执行（含删除）', command=accept).grid(row=0, column=1, sticky='e')
        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)
        return answer[0]

    def handle_control_event(self, kind, value):
        # Tk dispatches control requests, including those queued while a dialog is open.
        if kind == 'mcp_connect':
            self.root.deiconify()
            self.root.lift()
            self.connect()
        elif kind == 'mcp_bastion':
            token, expires = value
            allowed = self.bastion.shared and self.auth_stage == 'submitted' and not self.stop.is_set() and not self.human_active
            allowed = allowed and self.bastion.shared and self.auth_stage == 'submitted' and not self.human_active and time.monotonic() <= expires
            if not allowed:
                self.navigation = {'status': 'rejected'}
                self.navigation_pending = False
                return False

            def send_navigation():
                try:
                    self.send_line(token)
                    self.navigation = {'status': 'sent_wait_for_menu', 'input': token}
                except Exception:
                    self.navigation = {'status': 'send_outcome_unknown'}
                    self.bastion.shared = False
                finally:
                    self.navigation_pending = False

            threading.Thread(target=send_navigation, daemon=True).start()
        elif kind == 'mcp_submit':
            key, expires = value
            job = self.jobs.items[key]
            if time.monotonic() > expires or not self.target_ready or self.human_active:
                self.jobs.approve(key, False)
                return False
            reason = job['approval_reason']
            if reason:
                with self.jobs.lock:
                    if job['status'] != 'queued':
                        return False
                    job['status'] = 'awaiting_user_confirmation'
            approved = self.review_command(reason + '\n\n' + job['command']) if reason else True
            approved = approved and self.target_ready and not self.human_active and time.monotonic() <= expires
            wrapped = self.jobs.approve(key, approved)
            if wrapped:
                threading.Thread(target=self.execute_job, args=(key, wrapped), daemon=True).start()
        elif kind == 'mcp_shutdown':
            self.close()
            return True
        return False


def build_server(console):
    server = FastMCP('ssh-otp')

    @server.tool()
    def ssh_connect() -> dict:
        """Open local login window. User enters password/OTP and chooses target locally. Never send credentials as tool arguments."""
        if console.closed:
            return {'status': 'connector_closed', 'action': 'Restart this MCP server'}
        console.events.put(('mcp_connect', None))
        return {'status': 'login_window_requested', 'action': 'User completes local authentication, asset selection, and target confirmation'}

    @server.tool()
    def ssh_status() -> dict:
        """Read connection stage only. Authentication transcript and credentials are never returned."""
        return {'connected': bool(console.transport and console.transport.is_authenticated() and not console.stop.is_set()),
                'stage': console.auth_stage, 'target_confirmed': console.target_ready,
                'asset_menu_shared': console.bastion.shared, 'navigation': console.navigation,
                'active_job_id': console.jobs.active, 'window_closed': console.closed}

    @server.tool()
    def ssh_submit(command: str) -> dict:
        """Submit a single-line noninteractive command. Ordinary commands run directly. Deletion and opaque execution require LOCAL user confirmation. Returns job id; poll ssh_result. Never send credentials, OTP, sudo passwords or interactive programs."""
        if not console.target_ready or console.stop.is_set() or console.navigation_pending:
            raise ValueError('User must first authenticate and confirm the target Linux Shell in the local window')
        key = console.jobs.submit(command)
        console.events.put(('mcp_submit', (key, time.monotonic() + 300)))
        return {'job_id': key, 'status': 'queued', 'requires_confirmation': bool(deletion_reason(command))}

    @server.tool()
    def ssh_result(job_id: str) -> dict:
        """Read bounded job output and exit code. Authentication output is excluded. Running/unknown outcome is not success and must not be blindly retried."""
        return console.jobs.read(job_id, console.secrets)

    @server.tool()
    def ssh_bastion_view() -> dict:
        """Read user-approved post-OTP asset menu and navigation responses. Never returns login transcript. Ask user to click local Share asset menu first. Read displayed syntax; do not invent vendor commands."""
        return console.bastion.read(console.secrets)

    @server.tool()
    def ssh_bastion_send(menu_input: str) -> dict:
        """Search/select/connect through the user-shared bastion menu. Only a single hostname/IP/number/menu token, no whitespace or shell syntax. Never use for passwords or OTP. Poll ssh_bastion_view/status; after shell entry user confirms target locally."""
        if not MENU_TOKEN.fullmatch(menu_input):
            raise ValueError('Only a single asset-search/menu token is allowed; no shell commands or control characters')
        if not console.bastion.shared or console.auth_stage != 'submitted' or console.stop.is_set():
            raise ValueError('User must locally approve the authenticated asset menu; navigation is disabled in a Shell')
        if console.jobs.active or console.navigation_pending:
            raise ValueError('Another operation is pending')
        console.navigation_pending = True
        console.navigation = {'status': 'awaiting_user_confirmation', 'input': menu_input}
        console.events.put(('mcp_bastion', (menu_input, time.monotonic() + 300)))
        return console.navigation

    return server


def main():
    import sys
    if '--legacy' not in sys.argv:
        from universal_server import main as universal_main
        universal_main()
        return
    sys.argv.remove('--legacy')
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=2222)
    parser.add_argument('--user', required=True)
    parser.add_argument('--fingerprint', required=True)
    args = parser.parse_args()
    args.command_file = None
    logging.basicConfig(level=logging.WARNING)
    console = AgentConsole(args)
    server = build_server(console)

    def serve():
        try:
            server.run(transport='stdio')
        finally:
            console.events.put(('mcp_shutdown', None))

    threading.Thread(target=serve, daemon=True).start()
    console.root.mainloop()


if __name__ == '__main__':
    main()
