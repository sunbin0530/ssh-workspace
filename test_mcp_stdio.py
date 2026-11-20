"""End-to-end MCP client test. Creates a hidden GUI, never connects SSH."""
import asyncio
import json
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    server_path = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).with_name('mcp_server.py'))
    params = StdioServerParameters(command=sys.executable, args=[server_path, '--legacy', '--host', '192.0.2.10', '--user', 'tester', '--fingerprint', 'SHA256:' + 'A' * 43])
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {tool.name for tool in tools.tools} == {'ssh_connect', 'ssh_status', 'ssh_submit', 'ssh_result', 'ssh_bastion_view', 'ssh_bastion_send'}
            status = await session.call_tool('ssh_status', {})
            assert not status.isError
            payload = status.structuredContent or json.loads(status.content[0].text)
            assert payload['connected'] is False
            rejected = await session.call_tool('ssh_submit', {'command': 'hostname'})
            assert rejected.isError, 'Unauthenticated execution must be rejected'
            view = await session.call_tool('ssh_bastion_view', {})
            menu = view.structuredContent or json.loads(view.content[0].text)
            assert menu['output'] == '' and not menu['shared']
            denied = await session.call_tool('ssh_bastion_send', {'menu_input': '1'})
            assert denied.isError, 'Unshared navigation must be rejected'
            print('PASS: MCP initialize, discovery, status, unauthenticated execution blocked')


if __name__ == '__main__':
    asyncio.run(asyncio.wait_for(main(), timeout=30))
