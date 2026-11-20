"""Build platform packages from an explicit, credential-free file list."""
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parent
RUNTIME = (
    'adapters.py', 'bastion_state.py', 'command_policy.py', 'dialog_layout.py',
    'job_state.py', 'mcp_server.py', 'profiles.py', 'redaction.py', 'register_mcp.py',
    'requirements.txt', 'requirements.lock', 'ssh_otp.py', 'terminal_buffer.py', 'terminal_web.py',
    'universal_server.py', 'README.md', 'SECURITY.md', 'AUDIT.md', 'LICENSE', 'SKILL.md',
)
WEB = ('addon-fit.js', 'app.css', 'app.js', 'index.html', 'LICENSE-addon-fit',
       'LICENSE-xterm', 'xterm.css', 'xterm.js')


def main():
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    checksums = []
    for platform, installer in (('windows', 'install.ps1'), ('macos', 'install.sh')):
        output = dist / f'ssh-workspace-{platform}.zip'
        files = list(RUNTIME) + ['web/' + name for name in WEB] + [installer]
        with ZipFile(output, 'w', ZIP_DEFLATED) as archive:
            for name in files:
                info = ZipInfo('ssh-workspace/' + name)
                info.create_system = 3
                info.external_attr = (0o100755 if name == 'install.sh' else 0o100644) << 16
                info.compress_type = ZIP_DEFLATED
                archive.writestr(info, (ROOT / name).read_bytes())
        checksums.append(sha256(output.read_bytes()).hexdigest() + '  ' + output.name)
        print(output)
    (dist / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
