"""Local SSH console: pinned host key, private password/OTP dialogs, no credential files."""
import argparse
from contextlib import nullcontext
import base64
import hashlib
from pathlib import Path
import queue
import re
import socket
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext

import paramiko
from command_policy import deletion_reason
from adapters import authentication_options, get_adapter
from bastion_state import asset_menu_text

CHECKS = 'hostname\nuname -m\nkubectl config current-context\nkubectl get nodes -o wide\nkubectl get storageclass'
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)')
SHELL = re.compile(r'(?:^|\n)(?:\[[^\]\n]+@[^\]\n]+\][#$]|[^\s\n]+@[^\s\n]+:[^\n]*[#$])\s*$')
OTP_PROMPT = re.compile(r'(?:请输入[^\n]*(?:OTP|动态码|令牌|验证码)|(?:enter|input)[^\n]*(?:OTP|token|verification code))[^\n]*[:：]\s*$', re.I)


def send_terminal_line(channel, text, stop, pause=.04, abort_if=None, guard=None):
    """Legacy bastion reads input per packet; emulate typing, with CR separately."""
    if any(char in text for char in '\r\n\x00'):
        raise ValueError('Expected one terminal line without control characters')
    for char in text:
        with guard if guard is not None else nullcontext():
            if stop.is_set() or (abort_if and abort_if()):
                raise RuntimeError('Connection cancelled')
            channel.sendall(char.encode('utf-8'))
        if stop.wait(pause):
            raise RuntimeError('Connection cancelled')
    if stop.wait(.2):
        raise RuntimeError('Connection cancelled')
    with guard if guard is not None else nullcontext():
        if stop.is_set() or (abort_if and abort_if()):
            raise RuntimeError('Agent input paused by human takeover')
        channel.sendall(b'\r')


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


class Console:
    browser_handles_bastion_auth = False
    terminal_type = 'vt100'
    terminal_dimensions = (140, 40)

    def __init__(self, args, parent=None):
        self.args = args
        self.root = tk.Toplevel(parent) if parent else tk.Tk()
        self.adapter = get_adapter(getattr(args, 'adapter', 'company-bastion'))
        self.human_active = False
        self.root.title('Codex deployment — SSH / OTP v2')
        self.root.geometry('980x680')
        self.events = queue.Queue()
        self.stop = threading.Event()
        self.channel = None
        self.transport = None
        self.secrets = []
        self.pending_prompt = None
        self.send_lock = threading.Lock()
        self.auth_stage = 'disconnected'
        self.commands = Path(args.command_file).read_text(encoding='utf-8-sig') if args.command_file else CHECKS
        self.status = tk.StringVar(value=f'{args.user}@{args.host}:{args.port} — disconnected')
        tk.Label(self.root, textvariable=self.status, anchor='w').pack(fill='x')
        self.output = scrolledtext.ScrolledText(self.root, state='disabled', font=('Consolas', 10))
        self.output.pack(fill='both', expand=True)
        tk.Label(self.root, text='堡垒机资产选择：在下方输入编号或目标主机，点击发送。自定义命令每次均需确认。').pack(anchor='w')
        self.entry = tk.Entry(self.root, font=('Consolas', 11))
        self.entry.pack(fill='x')
        self.entry.bind('<Return>', lambda _: self.send_manual())
        buttons = tk.Frame(self.root)
        buttons.pack(fill='x')
        self.connect_button = tk.Button(buttons, text='连接（进入目标 Shell 后自动执行预览命令）', command=self.connect)
        self.connect_button.pack(side='left')
        tk.Button(buttons, text='发送 / 执行（删除需确认）', command=self.send_manual).pack(side='left')
        tk.Button(buttons, text='断开', command=self.disconnect).pack(side='left')
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        self.pump_timer = self.root.after(100, self.pump)

    def append(self, text):
        for secret in self.secrets:
            if secret:
                text = text.replace(secret, '[REDACTED]')
        self.output.configure(state='normal')
        self.output.insert('end', text)
        self.output.see('end')
        self.output.configure(state='disabled')

    def ask_secret(self, title, prompt):
        return self.ask_input(title, prompt, secret=True)

    def ask_input(self, title, prompt, secret=False):
        request = {'title': title, 'prompt': prompt, 'secret': secret, 'done': threading.Event(), 'value': None}
        self.events.put(('prompt', request))
        while not request['done'].wait(.1):
            if self.stop.is_set():
                raise RuntimeError('Connection cancelled')
        if request['value'] is None:
            raise RuntimeError('Authentication cancelled')
        return request['value']

    def choose_auth_method(self, options):
        menu = '\n'.join(f'[{key}] {label}' for key, label in options.items())
        return self.ask_input('选择堡垒机认证方式', menu)

    def connect(self):
        needs_review = any(deletion_reason(line) for line in self.commands.splitlines() if line.strip())
        if needs_review and not messagebox.askokcancel('删除 / 间接删除操作确认', '连接并进入目标 Linux Shell 后，将执行：\n\n' + self.commands + '\n\n请确认具体删除目标和影响。'):
            return
        self.stop.clear()
        self.connect_button.configure(state='disabled')
        threading.Thread(target=self.run, daemon=True).start()

    def authenticate(self, transport):
        def handler(title, instructions, prompts):
            answers = []
            for prompt, _echo in prompts:
                answers.append(self.ask_secret('SSH 认证', '\n'.join(filter(None, [title, instructions, prompt]))))
            return answers
        try:
            transport.auth_interactive(self.args.user, handler)
        except paramiko.BadAuthenticationType as error:
            if 'password' not in error.allowed_types:
                raise
            transport.auth_password(self.args.user, self.ask_secret('SSH 密码', '请输入 SSH 登录密码'))
        if not transport.is_authenticated():
            raise RuntimeError('Additional SSH authentication required')

    def send_line(self, text):
        with self.send_lock:
            if not self.channel:
                raise RuntimeError('Not connected')
            send_terminal_line(self.channel, text, self.stop,
                               pause=.005 if self.auth_stage == 'shell' else .04,
                               abort_if=lambda: self.human_active)

    def verify_host_key(self, key):
        actual = fingerprint(key)
        if actual != self.args.fingerprint:
            raise RuntimeError(f'Host key mismatch! Expected {self.args.fingerprint}; received {actual}')

    def on_terminal_data(self, data):
        pass

    def on_terminal_text(self, clean, tail, previous_stage):
        self.events.put(('output', clean))

    def on_terminal_idle(self, tail, idle_seconds):
        return False

    def on_terminal_opened(self):
        pass

    def run(self):
        sock = None
        try:
            if self.stop.is_set():
                return
            self.events.put(('status', '正在连接 SSH…'))
            sock = socket.create_connection((self.args.host, self.args.port), timeout=15)
            transport = paramiko.Transport(sock)
            self.transport = transport
            if self.stop.is_set():
                return
            transport.start_client(timeout=20)
            self.verify_host_key(transport.get_remote_server_key())
            self.events.put(('output', '主机公钥指纹已验证。\n'))
            self.authenticate(transport)
            if self.stop.is_set():
                return
            transport.set_keepalive(20)
            channel = transport.open_session(timeout=20)
            cols, rows = self.terminal_dimensions
            channel.get_pty(term=self.terminal_type, width=cols, height=rows)
            channel.invoke_shell()
            self.channel = channel
            if self.stop.is_set():
                return
            self.on_terminal_opened()
            self.auth_stage = self.adapter.initial_stage
            self.events.put(('status', 'SSH 已连接，等待堡垒机 / 目标主机'))
            tail = ''
            executed = False
            last_received = time.monotonic()
            import codecs
            decoder = codecs.getincrementaldecoder('utf-8')('replace')
            while not self.stop.is_set() and not channel.closed:
                if channel.recv_ready():
                    data = channel.recv(16384)
                    if not data:
                        break
                    self.on_terminal_data(data)
                    clean = ANSI.sub('', decoder.decode(data)).replace('\r', '')
                    tail = (tail + clean)[-6000:]
                    previous_stage = self.auth_stage
                    if self.adapter.post_login_mfa and self.auth_stage in ('menu', 'authenticating') and (
                        'user login success' in tail or asset_menu_text(tail)
                    ):
                        self.auth_stage = 'submitted'
                    self.on_terminal_text(clean, tail, previous_stage)
                    if previous_stage == 'shell' and self.auth_stage == 'submitted':
                        tail = ''
                    last_received = time.monotonic()
                elif channel.exit_status_ready():
                    break
                elif (idle_seconds := time.monotonic() - last_received) > .25:
                    # Wait until the entire prompt arrives before reacting. No LLM in this loop.
                    auth_pending = (not self.browser_handles_bastion_auth and self.adapter.post_login_mfa
                                    and self.auth_stage in ('menu', 'authenticating'))
                    options = authentication_options(tail) if auth_pending and not self.human_active else {}
                    if options:
                        self.auth_stage = 'selecting'
                        selection = self.choose_auth_method(options)
                        if selection not in options:
                            raise RuntimeError('请选择堡垒机提供的认证方式。')
                        self.send_line(selection)
                        self.auth_stage = 'authenticating'
                        tail = ''
                        self.events.put(('status', '已提交认证方式，等待堡垒机响应'))
                    elif auth_pending and not self.human_active and (challenge := OTP_PROMPT.search(tail)):
                        self.auth_stage = 'otp'
                        otp = self.ask_secret('堡垒机验证码', challenge[0].strip())
                        if not otp.isprintable():
                            raise RuntimeError('验证码包含无效字符。')
                        self.send_line(otp)
                        otp = None
                        self.auth_stage = 'authenticating'
                        tail = ''
                        self.events.put(('status', 'OTP 已提交，等待认证结果'))
                    elif (not executed or (self.browser_handles_bastion_auth and self.auth_stage == 'submitted')) and SHELL.search(tail):
                        # A conservative shell pattern: never run commands against a bastion menu.
                        self.auth_stage = 'shell'
                        if not executed:
                            for command_line in self.commands.splitlines():
                                self.send_line(command_line)
                        executed = True
                        tail = ''
                        self.events.put(('status', '已进入目标 Shell'))
                    elif self.on_terminal_idle(tail, idle_seconds):
                        # Require a new remote prompt before any further keepalive.
                        tail = ''
                time.sleep(.05)
        except Exception as error:
            self.events.put(('output', f'\n连接结束：{error}\n'))
        finally:
            self.disconnect()
            if sock:
                sock.close()
            self.events.put(('finished', None))

    def send_manual(self):
        text = self.entry.get()
        if not self.channel or self.channel.closed:
            messagebox.showinfo('未连接', '请先连接 SSH')
            return
        if self.auth_stage in ('selecting', 'otp'):
            messagebox.showinfo('认证进行中', '请在认证对话框中输入。')
            return
        if deletion_reason(text) and not messagebox.askokcancel('删除 / 间接删除操作确认', '将向当前远端终端发送：\n\n' + text + '\n\n请确认具体删除目标和影响。'):
            return
        try:
            self.send_line(text)
            self.entry.delete(0, 'end')
        except Exception as error:
            messagebox.showerror('发送失败', str(error))

    def pump(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == 'output':
                    self.append(value)
                elif kind == 'status':
                    self.status.set(value)
                elif kind == 'prompt':
                    self.pending_prompt = value
                    answer = simpledialog.askstring(value['title'], value['prompt'], show='*' if value['secret'] else '', parent=self.root)
                    if answer and value['secret']:
                        self.secrets.append(answer)
                    value['value'] = answer
                    value['done'].set()
                    self.pending_prompt = None
                elif kind == 'finished':
                    self.status.set('已断开')
                    self.connect_button.configure(state='normal')
                elif kind.startswith('mcp_'):
                    if self.handle_control_event(kind, value):
                        return
        except queue.Empty:
            pass
        self.pump_timer = self.root.after(100, self.pump)

    def handle_control_event(self, kind, value):
        return False

    def disconnect(self):
        self.stop.set()
        self.auth_stage = 'disconnected'
        if self.transport:
            self.transport.close()
        self.channel = None

    def close(self):
        self.disconnect()
        if self.pending_prompt:
            self.pending_prompt['done'].set()
        self.root.after_cancel(self.pump_timer)
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=2222)
    parser.add_argument('--user', required=True)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--command-file', help='UTF-8 commands, reviewed before connection and sent once upon shell detection')
    args = parser.parse_args()
    Console(args).root.mainloop()


if __name__ == '__main__':
    main()
