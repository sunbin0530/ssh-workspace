import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import queue
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import httpx
import uvicorn
from websockets.asyncio.client import connect as connect_ws

from starlette.testclient import TestClient
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from adapters import get_adapter
from bastion_state import BastionView
from job_state import Jobs
from profiles import Profile, ProfileStore
DEFAULT = Profile("test-bastion", "Test bastion", "192.0.2.10", "tester", adapter="company-bastion")
from terminal_buffer import TerminalBuffer
from terminal_web import make_app
from universal_server import HOST_VERIFICATION_COMMAND, SHELL_KEEPALIVE_INTERVAL, Manager, SessionConsole, build_server


class UniversalTests(unittest.TestCase):
    def test_profiles_reject_credentials_and_save_metadata(self):
        path = Path(__file__).parent / '.test-artifacts' / uuid.uuid4().hex / 'profiles.json'
        store = ProfileStore(path)
        self.assertEqual(store.list(), [])
        profile = Profile('test', 'Test', 'localhost', 'tester')
        store.save(profile)
        self.assertEqual(store.get('test'), profile)
        self.assertEqual(store.list(), [profile])
        with self.assertRaises(ValueError):
            Profile.parse({**asdict(profile), 'password': 'must-not-be-saved'})
        self.assertNotIn('password', path.read_text(encoding='utf-8'))

    def test_adapter_separates_direct_ssh_from_company_menu(self):
        self.assertEqual(get_adapter('ssh').initial_stage, 'shell')
        self.assertFalse(get_adapter('ssh').post_login_mfa)
        self.assertTrue(get_adapter('company-bastion').post_login_mfa)

    def test_ambiguous_session_is_rejected(self):
        manager = Manager.__new__(Manager)
        manager.lock = threading.RLock()
        first, second = object(), object()
        manager.sessions = {'a': first, 'b': second}
        with self.assertRaises(ValueError):
            manager.get()
        self.assertIs(manager.get('a'), first)
        self.assertIs(manager.get('b'), second)

    def test_session_list_is_recent_first_and_only_disconnected_records_can_be_removed(self):
        manager = Manager.__new__(Manager)
        manager.lock = threading.RLock()
        manager.local = lambda fn: fn()
        manager.status = lambda key, **kwargs: key
        closed = []
        first = SimpleNamespace(auth_stage='disconnected', stop=threading.Event(),
                                close=lambda: closed.append('a'))
        first.stop.set()
        second = SimpleNamespace(auth_stage='shell', stop=threading.Event())
        manager.sessions = {'a': first, 'b': second}
        app, token = make_app(manager, 19324)
        with TestClient(app, base_url='http://127.0.0.1:19324',
                        headers={'Authorization': 'Bearer ' + token}) as client:
            self.assertEqual(manager.statuses(), ['b', 'a'])
            self.assertEqual(client.post('/api/action', json={'session_id':'a','action':'select'}).status_code, 200)
            self.assertEqual(manager.statuses(), ['a', 'b'])
            self.assertEqual(client.post('/api/action', json={'session_id':'b','action':'remove'}).status_code, 400)
            self.assertEqual(client.post('/api/action', json={'session_id':'a','action':'remove'}).status_code, 200)
            self.assertEqual(manager.statuses(), ['b'])
            self.assertEqual(closed, ['a'])

    def test_disconnect_revokes_human_control_and_preserves_unknown_job(self):
        console = SessionConsole.__new__(SessionConsole)
        console.secrets = []
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.control_revision = 0
        console.manager = SimpleNamespace(lock=threading.RLock())
        console.controller = 'browser'
        console.human_active = True
        console.target_ready = True
        console.stop = threading.Event()
        console.bastion = SimpleNamespace(reset=lambda: None)
        console.jobs = Jobs()
        key = console.jobs.submit('pwd')
        console.transport = None
        console.navigation_pending = False
        console.disconnect()
        self.assertTrue(console.stop.is_set())
        self.assertEqual(console.auth_stage, 'disconnected')
        self.assertFalse(console.human_active)
        self.assertFalse(console.target_ready)
        self.assertIsNone(console.controller)
        self.assertEqual(console.jobs.read(key)['status'], 'disconnected_outcome_unknown')

    def test_reconnect_reuses_session_and_preserves_history_without_replaying_work(self):
        manager = Manager.__new__(Manager)
        manager.lock = threading.RLock()
        manager.local = lambda fn: fn()
        old = SessionConsole.__new__(SessionConsole)
        old.prompt_lock = threading.Lock()
        old.browser_prompt = None
        old.control_revision = 0
        old.profile = DEFAULT
        old.closed = False
        old.stop = threading.Event()
        old.stop.set()
        old.auth_stage = 'disconnected'
        old.connection_attempt = 1
        old.terminal_dimensions = (120, 35)
        old.shell_keepalive = False
        old.terminal = TerminalBuffer()
        old.terminal.append(b'old shell output')
        old.previous_results = {}
        old.secrets = []
        old.jobs = Jobs()
        job_id = old.jobs.submit('pwd')
        old.jobs.uncertain()
        old.close = lambda: setattr(old, 'closed', True)
        manager.sessions = {'original': old}

        new = SessionConsole.__new__(SessionConsole)
        new.profile = DEFAULT
        new.closed = False
        new.auth_stage = 'connecting'
        new.target_ready = False
        new.jobs = Jobs()
        new.events = queue.Queue()
        new.terminal = TerminalBuffer()
        app, token = make_app(manager, 19326)
        with patch('universal_server.SessionConsole', return_value=new):
            with TestClient(app, base_url='http://127.0.0.1:19326',
                            headers={'Authorization': 'Bearer ' + token}) as client:
                request = {'session_id': 'original', 'action': 'reconnect'}
                response = client.post('/api/action', json=request)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['session_id'], 'original')
                self.assertEqual(response.json()['connection_attempt'], 2)
                self.assertEqual(client.post('/api/action', json=request).status_code, 400)
        self.assertEqual(list(manager.sessions), ['original'])
        self.assertTrue(old.closed)
        self.assertEqual(new.terminal_dimensions, (120, 35))
        self.assertFalse(new.shell_keepalive)
        self.assertIn(b'old shell output', new.terminal.since(0)[1])
        self.assertEqual(new.read_job(job_id)['status'], 'disconnected_outcome_unknown')
        self.assertFalse(new.target_ready)
        self.assertIsNone(new.jobs.active)
        self.assertEqual(new.events.get_nowait(), ('mcp_connect', None))
        self.assertTrue(new.events.empty())

    def test_terminal_overflow_replays_bounded_bytes_without_touching_jobs(self):
        buffer = TerminalBuffer(limit=5)
        buffer.append(b'12345678')
        cursor, data, reset = buffer.since(0)
        self.assertEqual((cursor, data, reset), (8, b'45678', True))
        buffer.append(b'9')
        self.assertEqual(buffer.since(cursor), (9, b'9', False))

    def test_resize_before_ssh_terminal_opens_is_applied_after_open(self):
        console = SessionConsole.__new__(SessionConsole)
        console.secrets = []
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.control_revision = 0
        console.manager = SimpleNamespace(lock=threading.RLock())
        console.stop = threading.Event()
        console.channel = None
        console.resize_terminal(96, 25)
        calls = []
        console.channel = SimpleNamespace(closed=False, resize_pty=lambda **size: calls.append(size))
        console.on_terminal_opened()
        console.resize_terminal(180, 50)
        self.assertEqual(calls, [{'width': 96, 'height': 25}, {'width': 180, 'height': 50}])
        self.assertEqual(console.terminal_type, 'xterm-256color')

    def test_new_target_requires_successful_host_verification_and_readback(self):
        manager = Manager.__new__(Manager)
        manager.lock = threading.RLock()
        console = SessionConsole.__new__(SessionConsole)
        console.secrets = []
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.control_revision = 0
        console.manager = manager
        manager.sessions = {'session': console}
        console.profile = DEFAULT
        console.adapter = get_adapter(DEFAULT.adapter)
        console.connection_attempt = 1
        console.control_revision = 0
        console.closed = False
        console.stop = threading.Event()
        console.channel = SimpleNamespace(closed=False)
        console.transport = SimpleNamespace(is_authenticated=lambda: True)
        console.auth_stage = 'shell'
        console.human_active = console.target_ready = False
        console.navigation_pending = False
        console.navigation = {}
        console.target_hint = None
        console.verified_host = None
        console.verification_job = None
        console.shell_keepalive = False
        console.previous_results = {}
        console.secrets = []
        console.jobs = Jobs()
        console.events = queue.Queue()
        console.bastion = BastionView()
        server = build_server(manager)

        def call(tool, **args):
            return asyncio.run(server.call_tool(tool, {'session_id': 'session', **args}))

        console.on_terminal_text('[root@first-host ~]# ', '[root@first-host ~]# ', 'shell')
        self.assertEqual(console.target_hint, 'root@first-host')
        self.assertEqual(console.events.get_nowait()[0], 'output')
        console.queue_target_confirmation(0)
        _, confirmation = console.events.get_nowait()
        console.confirm_target(confirmation)
        self.assertEqual(manager.statuses()[0]['verification_command'], HOST_VERIFICATION_COMMAND)
        call('ssh_status')
        with self.assertRaisesRegex(Exception, 'First verify'):
            call('ssh_submit', command='pwd')
        call('ssh_verify_host')
        verification_id = console.jobs.active
        console.jobs.approve(verification_id, True)
        console.jobs.feed(f'\nSSHOTP_{verification_id}_BEGIN\nfirst-host\n192.0.2.20 192.0.2.21 \n'
                          f'SSHOTP_{verification_id}_END:0\n')
        with self.assertRaisesRegex(Exception, 'First verify'):
            call('ssh_submit', command='pwd')
        call('ssh_result', job_id=verification_id)
        self.assertEqual(manager.statuses()[0]['verified_host']['addresses'], ['192.0.2.20', '192.0.2.21'])
        call('ssh_submit', command='pwd')
        job_id = console.jobs.active
        console.jobs.approve(job_id, False)

        console.on_terminal_text('[root@second-host ~]# ', '[root@second-host ~]# ', 'shell')
        self.assertFalse(console.target_ready)
        console.confirm_target(1)
        self.assertFalse(console.target_ready)
        console.confirm_target(2)
        call('ssh_result', job_id=verification_id)
        self.assertIsNone(manager.statuses()[0]['verified_host'])
        with self.assertRaisesRegex(Exception, 'First verify'):
            call('ssh_submit', command='pwd')

    def test_http_and_websocket_reject_untrusted_access(self):
        manager = SimpleNamespace(profiles=SimpleNamespace(list=lambda: [DEFAULT]))
        app, token = make_app(manager, 19321)
        with TestClient(app, base_url='http://127.0.0.1:19321') as client:
            self.assertEqual(client.get('/api/profiles').status_code, 401)
            self.assertEqual(client.get('/api/profiles', headers={'Authorization': 'Bearer '+token}).status_code, 200)
            self.assertEqual(client.get('/api/profiles', headers={'Authorization': 'Bearer '+token, 'Origin':'https://untrusted.invalid'}).status_code, 403)
            self.assertEqual(client.get('/', headers={'Host':'untrusted.invalid'}).status_code, 403)
            with self.assertRaises(Exception):
                with client.websocket_connect('/terminal/any', headers={'Origin':'https://untrusted.invalid'}, subprotocols=[token]):
                    self.fail('Untrusted websocket must not be accepted')

    def test_bastion_menu_return_revokes_target_and_blocks_old_job(self):
        console = SessionConsole.__new__(SessionConsole)
        console.secrets = []
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.control_revision = 0
        console.manager = SimpleNamespace(lock=threading.RLock())
        console.adapter = get_adapter(DEFAULT.adapter)
        console.auth_stage = 'shell'
        console.target_ready = True
        console.human_active = False
        console.target_hint = 'root@target'
        console.verified_host = {'hostname': 'target', 'addresses': ['10.0.0.1']}
        console.verification_job = None
        console.control_revision = 2
        console.stop = threading.Event()
        console.bastion = BastionView()
        console.bastion.grant('old asset menu')
        console.jobs = Jobs()
        console.events = queue.Queue()
        console.send_lock = threading.Lock()
        packets = []
        console.channel = SimpleNamespace(closed=False, sendall=packets.append)
        key = console.jobs.submit('pwd')
        wrapped = console.jobs.approve(key, True)

        partial = '历史会话(1) :\n操作命令:\n  [l] 显示SSH资源列表\n  [s] 搜索资源\n'
        console.on_terminal_text(partial, partial, 'shell')
        self.assertTrue(console.target_ready)
        console.on_terminal_text('> ', partial + '> ', 'shell')
        self.assertEqual(console.auth_stage, 'submitted')
        self.assertFalse(console.target_ready)
        self.assertIsNone(console.verified_host)
        self.assertEqual(console.control_revision, 3)
        self.assertFalse(console.bastion.shared)
        self.assertIn('[s]', console.bastion.candidate)
        console.execute_job(key, wrapped)
        self.assertEqual(packets, [])
        self.assertEqual(console.jobs.read(key)['status'], 'disconnected_outcome_unknown')

    def test_shell_keepalive_only_sends_colon_to_a_verified_idle_shell(self):
        packets = []
        manager = Manager.__new__(Manager)
        manager.lock = threading.RLock()
        console = SessionConsole.__new__(SessionConsole)
        console.secrets = []
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.control_revision = 0
        manager.sessions = {'test': console}
        console.manager = manager
        console.auth_stage = 'shell'
        console.target_ready = True
        console.verified_host = {'hostname': 'target', 'addresses': ['10.0.0.1']}
        console.target_hint = 'root@target'
        console.human_active = False
        console.controller = None
        console.jobs = Jobs()
        console.navigation_pending = False
        console.stop = threading.Event()
        console.prompt_view = lambda: None
        console.send_lock = threading.Lock()
        console.channel = SimpleNamespace(closed=False, recv_ready=lambda: False, send_ready=lambda: True,
                                          send=lambda data: packets.append(data) or len(data))
        console.shell_keepalive = False
        prompt = '[root@target ~]# '
        idle = SHELL_KEEPALIVE_INTERVAL

        self.assertFalse(console.on_terminal_idle(prompt, idle))
        manager.set_shell_keepalive('test', True)
        self.assertFalse(console.on_terminal_idle(prompt, idle - 1))
        self.assertFalse(console.on_terminal_idle('[root@other ~]# ', idle))
        self.assertFalse(console.on_terminal_idle('正在运行', idle))
        for attr, paused in [('auth_stage', 'submitted'), ('human_active', True), ('target_ready', False),
                             ('verified_host', None), ('navigation_pending', True)]:
            original = getattr(console, attr)
            setattr(console, attr, paused)
            self.assertFalse(console.on_terminal_idle(prompt, idle), attr)
            setattr(console, attr, original)
        key = console.jobs.submit('pwd')
        self.assertFalse(console.on_terminal_idle(prompt, idle))
        console.jobs.approve(key, False)
        console.channel.recv_ready = lambda: True
        self.assertFalse(console.on_terminal_idle(prompt, idle))
        console.channel.recv_ready = lambda: False
        self.assertTrue(console.on_terminal_idle(prompt, idle))
        self.assertEqual(packets, [b':\r'])

    def test_human_input_requires_takeover_and_never_becomes_job_output(self):
        packets = []
        channel = SimpleNamespace(closed=False, sendall=packets.append)
        console = SimpleNamespace(channel=channel, closed=False, stop=threading.Event(), prompt_view=lambda: None,
            auth_stage='shell', controller=None, human_active=False, target_ready=True, control_revision=0,
            bastion=SimpleNamespace(shared=True), jobs=Jobs(), send_lock=threading.Lock(),
            events=queue.Queue(), terminal=TerminalBuffer())
        console.invalidate_target = lambda: (setattr(console, 'target_ready', False), setattr(console, 'control_revision', console.control_revision + 1), console.jobs.uncertain())
        console.queue_target_confirmation = lambda revision: console.events.put(('mcp_confirm', revision))
        manager = SimpleNamespace(get=lambda key: console, lock=threading.RLock())
        app, token = make_app(manager, 19322)
        with TestClient(app, base_url='http://127.0.0.1:19322') as client:
            with client.websocket_connect('/terminal/test', headers={'Origin':'http://127.0.0.1:19322', 'Host':'127.0.0.1:19322'}, subprotocols=[token]) as ws:
                ws.send_json({'type':'input', 'data':'not-authorized'})
                self.assertIn('error', ws.receive_json())
            self.assertEqual(packets, [])
            with client.websocket_connect('/terminal/test', headers={'Origin':'http://127.0.0.1:19322', 'Host':'127.0.0.1:19322'}, subprotocols=[token]) as ws:
                ws.send_json({'type':'takeover'})
                self.assertEqual(ws.receive_json(), {'control': 'human'})
                ws.send_json({'type':'input', 'data':'human-only'})
                ws.send_json({'type':'release'})
                self.assertEqual(ws.receive_json(), {'control': 'released'})
            self.assertEqual(packets, [b'human-only'])
            self.assertFalse(console.target_ready)
            self.assertEqual(console.jobs.items, {})
            events = []
            while not console.events.empty():
                events.append(console.events.get_nowait())
            self.assertIn(('mcp_confirm', 1), events)

    def test_browser_approval_is_scoped_and_single_use(self):
        console = SessionConsole.__new__(SessionConsole)
        console.secrets = []
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.control_revision = 0
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.stop = threading.Event()
        manager = SimpleNamespace(get=lambda key: console, prompts=lambda: [console.prompt_view()])
        app, token = make_app(manager, 19323)
        result = []
        worker = threading.Thread(target=lambda: result.append(console.review_command('rm example')), daemon=True)
        worker.start()
        try:
            deadline = time.monotonic() + 2
            while console.prompt_view() is None and time.monotonic() < deadline:
                time.sleep(.01)
            headers = {'Authorization': 'Bearer ' + token}
            with TestClient(app, base_url='http://127.0.0.1:19323') as client:
                self.assertEqual(client.get('/api/prompts').status_code, 401)
                prompt = client.get('/api/prompts', headers=headers).json()[0]
                self.assertEqual(prompt['content'], 'rm example')
                answer = {'session_id': 'test', 'prompt_id': 'stale', 'approved': True}
                self.assertEqual(client.post('/api/prompt-answer', headers=headers, json=answer).status_code, 400)
                answer.update(prompt_id=prompt['id'], approved=False)
                self.assertEqual(client.post('/api/prompt-answer', headers=headers, json=answer).status_code, 200)
                self.assertEqual(client.post('/api/prompt-answer', headers=headers, json=answer).status_code, 400)
                worker.join(2)
                self.assertEqual(result, [False])
        finally:
            console.stop.set()
            worker.join(2)

    def test_bastion_login_accepts_terminal_input_and_keeps_auth_echo_out_of_asset_menu(self):
        packets = []
        console = SessionConsole.__new__(SessionConsole)
        console.secrets = []
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.control_revision = 0
        console.channel = SimpleNamespace(closed=False, sendall=packets.append)
        console.closed = False
        console.stop = threading.Event()
        console.invalidate_target = lambda: (setattr(console, 'target_ready', False), setattr(console, 'control_revision', console.control_revision + 1))
        console.auth_stage = 'menu'
        console.control_revision = 0
        console.controller = None
        console.human_active = False
        console.target_ready = False
        console.prompt_view = lambda: None
        console.jobs = Jobs()
        console.bastion = BastionView()
        console.send_lock = threading.Lock()
        console.events = queue.Queue()
        console.terminal = TerminalBuffer()
        manager = SimpleNamespace(get=lambda key: console, lock=threading.RLock())
        app, token = make_app(manager, 19325)
        origin = 'http://127.0.0.1:19325'
        with TestClient(app, base_url=origin) as client:
            headers = {'Origin': origin, 'Host': '127.0.0.1:19325'}
            with client.websocket_connect('/terminal/test', headers=headers, subprotocols=[token]) as ws:
                ws.send_json({'type':'takeover', 'automatic':True})
                self.assertEqual(ws.receive_json(), {'control': 'human'})
                for data in ('1', '\r', 'fake-otp', '\r'):
                    ws.send_json({'type':'input', 'data':data})
                ws.send_json({'type':'unknown'})
                ws.receive_json()
        self.assertEqual(packets, [b'1', b'\r', b'fake-otp', b'\r'])
        self.assertFalse(console.target_ready)
        console.auth_stage = 'submitted'
        chunk = 'fake-otp\nuser login success\n操作命令:\n[s] 搜索资源\n> '
        console.on_terminal_text(chunk, chunk, 'menu')
        self.assertEqual(console.bastion.candidate, '操作命令:\n[s] 搜索资源\n> ')

    def test_pending_ssh_challenge_cannot_be_answered_after_transport_closes(self):
        console = SessionConsole.__new__(SessionConsole)
        console.secrets = []
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.control_revision = 0
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.stop = threading.Event()
        active = threading.Event()
        active.set()
        console.transport = SimpleNamespace(is_active=active.is_set)
        result = []
        worker = threading.Thread(target=lambda: result.append(
            console.request_prompt('secret', 'SSH authentication', 'Password:', timeout=2)))
        worker.start()
        try:
            deadline = time.monotonic() + 1
            while console.prompt_view() is None and time.monotonic() < deadline:
                time.sleep(.01)
            prompt = console.prompt_view()
            self.assertIsNotNone(prompt)
            active.clear()
            self.assertIsNone(console.prompt_view())
            with self.assertRaises(ValueError):
                console.answer_prompt(prompt['id'], True, 'unused')
        finally:
            console.stop.set()
            worker.join(2)
        self.assertEqual(result, [None])

    def test_actual_loopback_http_and_websocket(self):
        terminal = TerminalBuffer()
        terminal.append(b'\x1b[32mtest shell\x1b[0m\r\n')
        console = SimpleNamespace(terminal=terminal, controller=None)
        manager = SimpleNamespace(get=lambda key: console, lock=threading.RLock(),
                                  profiles=SimpleNamespace(list=lambda: [DEFAULT]))
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        app, token = make_app(manager, port)
        server = uvicorn.Server(uvicorn.Config(app, log_level='error', access_log=False, proxy_headers=False))
        thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(.025)
            self.assertTrue(server.started)
            origin = f'http://127.0.0.1:{port}'
            with httpx.Client(base_url=origin, trust_env=False) as client:
                self.assertIn('SSH Workspace', client.get('/').text)
                self.assertGreater(len(client.get('/static/xterm.js').content), 10000)
                self.assertEqual(client.get('/api/profiles', headers={'Authorization':'Bearer '+token}).status_code, 200)

            async def receive():
                async with connect_ws(f'ws://127.0.0.1:{port}/terminal/test', origin=origin, subprotocols=[token], proxy=None) as ws:
                    self.assertEqual(await asyncio.wait_for(ws.recv(), 3), b'\x1b[32mtest shell\x1b[0m\r\n')

            asyncio.run(receive())
        finally:
            server.should_exit = True
            thread.join(5)
            listener.close()


async def smoke(server_path=None):
    server_path = server_path or str(Path(__file__).with_name('mcp_server.py'))
    params = StdioServerParameters(command=sys.executable, args=[server_path])
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {tool.name for tool in tools.tools} == {'ssh_profiles','ssh_connect','ssh_open_ui','ssh_sessions','ssh_status','ssh_verify_host','ssh_submit','ssh_result','ssh_bastion_view','ssh_bastion_send'}
            profiles = await session.call_tool('ssh_profiles', {})
            assert not profiles.isError
            sessions = await session.call_tool('ssh_sessions', {})
            assert not sessions.isError
            rejected = await session.call_tool('ssh_submit', {'command':'pwd'})
            assert rejected.isError
            print('PASS: universal MCP handshake, 10 tools, profile/session discovery, no-session command blocked')


if __name__ == '__main__':
    if '--smoke' in sys.argv:
        path = sys.argv[2] if len(sys.argv)>2 else None
        asyncio.run(asyncio.wait_for(smoke(path), 30))
    else:
        unittest.main()
