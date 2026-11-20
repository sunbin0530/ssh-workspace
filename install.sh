#!/bin/sh
set -eu

usage() {
    printf '%s\n' 'Usage: sh install.sh [--python /path/to/python3] [--register-codex]'
}

python_exe=python3
register_codex=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --python)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                usage >&2
                exit 2
            fi
            python_exe=$2
            shift 2
            ;;
        --register-codex)
            register_codex=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$(uname -s)" != Darwin ]; then
    printf '%s\n' 'This installer is for macOS.' >&2
    exit 1
fi

package_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
local_python="$package_dir/.venv/bin/python"
if [ ! -x "$local_python" ]; then
    if ! "$python_exe" -c 'import sys, tkinter; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
        printf '%s\n' 'Python 3.11+ with Tcl/Tk is required. Select it with --python.' >&2
        exit 1
    fi
    "$python_exe" -m venv "$package_dir/.venv"
fi

"$local_python" -c 'import sys, tkinter; sys.exit(0 if sys.version_info >= (3, 11) else 1)'
"$local_python" -m pip install --require-hashes -r "$package_dir/requirements.lock"
"$local_python" -c 'import tkinter, paramiko, mcp, starlette, uvicorn, websockets'

if [ "$register_codex" = true ]; then
    "$local_python" "$package_dir/register_mcp.py"
fi

printf 'MCP command: %s\nMCP argument: %s\n' "$local_python" "$package_dir/mcp_server.py"
