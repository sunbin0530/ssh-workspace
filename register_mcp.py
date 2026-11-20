"""Append only this MCP entry, preserving existing settings and creating a backup."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import shutil
import sys
import tomllib


def register(config, executable, server):
    config = Path(config)
    previous = config.read_text(encoding='utf-8') if config.exists() else ''
    data = tomllib.loads(previous)
    entry = {'command': str(executable), 'args': [str(server)],
             'startup_timeout_sec': 30, 'tool_timeout_sec': 60,
             'env': {'PYTHONIOENCODING': 'utf-8', 'PYTHONUTF8': '1'}}
    existing = data.get('mcp_servers', {}).get('ssh_otp')
    if existing is not None:
        if existing == entry:
            return 'Already registered'
        raise ValueError('ssh_otp already exists with different configuration; refusing to overwrite')
    addition = '\n\n[mcp_servers.ssh_otp]\n' + '\n'.join([
        'command = ' + json.dumps(entry['command']),
        'args = ' + json.dumps(entry['args']),
        'startup_timeout_sec = 30', 'tool_timeout_sec = 60',
        'env = { PYTHONIOENCODING = "utf-8", PYTHONUTF8 = "1" }', ''])
    tomllib.loads(previous + addition)
    config.parent.mkdir(parents=True, exist_ok=True)
    if config.exists():
        backup = config.with_name(config.name + '.ssh-otp-backup-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
        shutil.copy2(config, backup)
    with config.open('a', encoding='utf-8', newline='\n') as stream:
        stream.write(addition)
    return 'Registered ssh_otp; existing settings preserved'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, default=Path.home() / '.codex' / 'config.toml')
    args = parser.parse_args()
    print(register(args.config, Path(sys.executable), Path(__file__).with_name('mcp_server.py')))
