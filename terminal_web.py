"""Human-only loopback UI. Its capability is never returned by MCP tools."""
import asyncio
from dataclasses import asdict
import hmac
import json
from pathlib import Path
import secrets
import uuid

from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocketDisconnect

from profiles import Profile

STATIC = Path(__file__).with_name('web')


def make_app(manager, port):
    token = secrets.token_urlsafe(32)
    origin = f'http://127.0.0.1:{port}'
    expected_host = f'127.0.0.1:{port}'

    def authorized(headers):
        return hmac.compare_digest(headers.get('authorization', ''), 'Bearer ' + token)

    class Guard(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.headers.get('host') != expected_host:
                return JSONResponse({'error': 'Invalid host'}, status_code=403)
            if request.headers.get('origin') not in (None, origin):
                return JSONResponse({'error': 'Invalid origin'}, status_code=403)
            if request.url.path.startswith('/api/') and not authorized(request.headers):
                return JSONResponse({'error': 'Unauthorized'}, status_code=401)
            try:
                response = await call_next(request)
            except (ValueError, KeyError, TypeError) as error:
                response = JSONResponse({'error': str(error)}, status_code=400)
            response.headers.update({
                'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
                'X-Content-Type-Options': 'nosniff',
                'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws://" + expected_host + "; object-src 'none'; frame-ancestors 'none'",
            })
            return response

    async def index(request):
        return FileResponse(STATIC / 'index.html')

    async def asset(request):
        # No arbitrary filesystem path; third-party assets are packaged locally.
        files = {'app.js', 'app.css', 'xterm.js', 'xterm.css', 'addon-fit.js'}
        name = request.path_params['name']
        if name not in files:
            return JSONResponse({'error': 'Not found'}, status_code=404)
        return FileResponse(STATIC / name)

    async def profiles(request):
        if request.method == 'GET':
            return JSONResponse([asdict(item) for item in manager.profiles.list()])
        if int(request.headers.get('content-length', '0')) > 16384:
            return JSONResponse({'error': 'Profile too large'}, status_code=413)
        profile = Profile.parse(await request.json())
        manager.profiles.save(profile)
        return JSONResponse({'saved': profile.id})

    async def sessions(request):
        manager.browser_heartbeat()
        return JSONResponse(manager.statuses(browser=True))

    async def prompts(request):
        return JSONResponse(manager.prompts())

    async def answer_prompt(request):
        value = await request.json()
        approved = value['approved']
        answer = value.get('value', '')
        if type(approved) is not bool or not isinstance(answer, str) or len(answer) > 32768:
            raise ValueError('Invalid prompt answer')
        manager.get(value['session_id']).answer_prompt(value['prompt_id'], approved, answer)
        return JSONResponse({'status': 'accepted'})

    async def connect(request):
        value = await request.json()
        result = await asyncio.to_thread(manager.connect, value['profile_id'])
        return JSONResponse(result)

    async def action(request):
        value = await request.json()
        key = value['session_id']
        if not isinstance(key, str) or not key:
            raise ValueError('请选择会话。')
        if value['action'] == 'select':
            manager.select_session(key)
            return JSONResponse({'status': 'selected'})
        if value['action'] == 'reconnect':
            return JSONResponse(await asyncio.to_thread(manager.reconnect, key))
        if value['action'] == 'remove':
            await asyncio.to_thread(manager.remove_session, key)
            return JSONResponse({'status': 'removed'})
        if value['action'] == 'keepalive':
            manager.set_shell_keepalive(key, value.get('enabled'))
            return JSONResponse({'status': 'updated'})
        console = manager.get(key)
        if value['action'] == 'confirm':
            console.queue_target_confirmation(value.get('target_revision'))
            return JSONResponse({'status': 'requested'})
        actions = {'share': 'mcp_share', 'disconnect': 'mcp_disconnect'}
        if value['action'] not in actions:
            raise ValueError('Unknown local action')
        console.events.put((actions[value['action']], None))
        return JSONResponse({'status': 'requested'})

    async def shutdown(request):
        # Let the browser receive the acknowledgement before stopping its local server.
        return JSONResponse({'status': 'closing'}, background=BackgroundTask(manager.local, manager.root.quit))

    async def terminal(socket):
        # Cookies/query strings are deliberately not used for terminal authorization.
        if (socket.headers.get('host') != expected_host or socket.headers.get('origin') != origin or
                token not in socket.scope.get('subprotocols', [])):
            await socket.close(code=1008)
            return
        try:
            console = manager.get(socket.path_params['session_id'])
        except ValueError:
            await socket.close(code=1008)
            return
        await socket.accept(subprotocol=token)
        owner = uuid.uuid4().hex

        async def send_output():
            cursor = 0
            while True:
                if getattr(console, 'closed', False):
                    await socket.close(code=1000)
                    return
                cursor, data, reset = console.terminal.since(cursor)
                if reset:
                    await socket.send_json({'reset': True})
                if data:
                    await socket.send_bytes(data)
                await asyncio.sleep(.05)

        outgoing = asyncio.create_task(send_output())
        try:
            while True:
                message = await socket.receive_text()
                if len(message) > 65536:
                    raise ValueError('Terminal input too large')
                value = json.loads(message)
                if value['type'] == 'takeover':
                    with manager.lock:
                        if value.get('automatic') is True and (console.auth_stage != 'menu' or console.controller is not None):
                            continue
                        if console.prompt_view():
                            raise ValueError('请先处理页面中的会话提示。')
                        if not console.channel or console.channel.closed or console.closed or console.stop.is_set():
                            raise ValueError('Wait for an active SSH terminal')
                        if console.controller not in (None, owner):
                            raise ValueError('Another browser tab owns this terminal')
                        console.controller = owner
                        # Block tool writes immediately, before the UI processes the event.
                        console.human_active = True
                        console.invalidate_target()
                        console.bastion.shared = False
                    console.events.put(('mcp_human', True))
                    await socket.send_json({'control': 'human'})
                elif value['type'] == 'release':
                    release_error = None
                    with manager.lock:
                        if console.controller == owner:
                            console.controller = None
                            console.human_active = False
                            try:
                                if console.auth_stage == 'shell':
                                    console.queue_target_confirmation(console.control_revision)
                                console.events.put(('mcp_human', False))
                            except ValueError as error:
                                console.controller = owner
                                console.human_active = True
                                release_error = str(error)
                        else:
                            release_error = '此窗口未持有终端控制权。'
                    if release_error:
                        await socket.send_json({'error': release_error})
                    else:
                        await socket.send_json({'control': 'released'})
                elif value['type'] == 'input':
                    if console.controller != owner or not console.human_active:
                        raise ValueError('Take over the terminal before typing')
                    text = value['data']
                    if not isinstance(text, str) or len(text) > 32768:
                        raise ValueError('Invalid terminal input')

                    def send():
                        with console.send_lock:
                            channel = console.channel
                            if channel and not channel.closed and not console.stop.is_set() and console.controller == owner:
                                channel.sendall(text.encode('utf-8'))
                    await asyncio.to_thread(send)
                elif value['type'] == 'resize':
                    cols, rows = int(value['cols']), int(value['rows'])
                    if not 20 <= cols <= 500 or not 5 <= rows <= 200:
                        raise ValueError('Invalid terminal dimensions')
                    await asyncio.to_thread(console.resize_terminal, cols, rows)
                else:
                    raise ValueError('Unknown terminal message')
        except (WebSocketDisconnect, RuntimeError):
            pass
        except (ValueError, KeyError, TypeError) as error:
            await socket.send_json({'error': str(error)})
            await socket.close(code=1008)
        finally:
            outgoing.cancel()
            try:
                await outgoing
            except (asyncio.CancelledError, RuntimeError):
                pass
            with manager.lock:
                if console.controller == owner:
                    console.controller = None
                    console.human_active = False
                    console.invalidate_target()
                    console.events.put(('mcp_human', False))

    app = Starlette(routes=[
        Route('/', index), Route('/static/{name}', asset),
        Route('/api/profiles', profiles, methods=['GET', 'POST']),
        Route('/api/sessions', sessions), Route('/api/connect', connect, methods=['POST']),
        Route('/api/prompts', prompts), Route('/api/prompt-answer', answer_prompt, methods=['POST']),
        Route('/api/action', action, methods=['POST']), Route('/api/shutdown', shutdown, methods=['POST']),
        WebSocketRoute('/terminal/{session_id}', terminal),
    ])
    app.add_middleware(Guard)
    return app, token
