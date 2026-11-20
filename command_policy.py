"""Recognize explicit deletion; the Agent assesses scripts and indirect effects."""
import re
import shlex
import ast

DELETE_PROGRAMS = {'rm', 'rmdir', 'unlink', 'shred', 'srm', 'del', 'erase', 'rd',
                   'remove-item', 'clear-content', 'truncate', 'mkfs', 'wipefs', 'dd'}


def unwrap_command(words):
    words = list(words)
    wrappers = {
        'sudo': {'-u', '-g', '-h', '-p', '-c', '--user', '--group'},
        'env': {'-u', '--unset', '-c', '--chdir'},
        'xargs': {'-n', '-p', '-i', '-l', '-s', '--max-args', '--replace'},
        'timeout': set(), 'command': set(), 'exec': {'-a'},
        'nohup': set(), 'busybox': set(),
    }
    while words:
        if re.match(r'^[a-z_][a-z0-9_]*=', words[0]):
            words.pop(0)
            continue
        name = words[0].rsplit('/', 1)[-1]
        if name not in wrappers:
            break
        words.pop(0)
        while words and words[0].startswith('-'):
            flag = words.pop(0)
            if flag == '--':
                break
            if flag in wrappers[name] and words:
                words.pop(0)
        if name == 'timeout' and words:
            words.pop(0)
    return words


def python_deletes(body):
    try:
        tree = ast.parse(body)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ('unlink', 'rmdir', 'rmtree'):
                return True
            if node.func.attr == 'remove' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                return True
    return False


def has_shell_expansion(command):
    quote = None
    index = 0
    while index < len(command):
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if char == '\\':
            index += 2
            continue
        if char == '"':
            quote = None if quote == '"' else '"'
        elif char == "'" and quote is None:
            quote = "'"
        elif char == '`' or command[index:index + 2] == '$(':
            return True
        elif quote is None and command[index:index + 2] in ('<(', '>('):
            return True
        index += 1
    return False


def deletion_reason(command, depth=0):
    if depth > 8:
        return None
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|()< >')
        lexer.whitespace_split = True
        words = list(lexer)
    except ValueError:
        return None
    lower = [word.lower() for word in words]
    segments = []
    segment = []
    for word in lower:
        if word in (';', '&&', '||', '|', '(', ')', '&'):
            if segment:
                segments.append(segment)
            segment = []
        else:
            segment.append(word)
    if segment:
        segments.append(segment)
    commands = []
    for segment in segments:
        # Wrappers do not themselves trigger approval. Inspect a visible command.
        segment = unwrap_command(segment)
        if not segment:
            continue
        commands.append(segment)
        name = segment[0].rsplit('/', 1)[-1]
        if name in DELETE_PROGRAMS or name.startswith('mkfs.'):
            return '命令包含明确的删除、清空或磁盘覆盖操作'
        if name in ('sh', 'bash', 'zsh', 'dash', 'eval'):
            for body in segment[1:]:
                if not body.startswith('-') and (reason := deletion_reason(body, depth + 1)):
                    return reason
        if name.startswith(('python', 'node', 'perl', 'ruby', 'powershell', 'pwsh')):
            if name.startswith('python') and '-c' in segment:
                index = segment.index('-c') + 1
                if index < len(segment) and python_deletes(segment[index]):
                    return 'Python 中包含明确的删除调用'
            if any(re.search(r'\b(?:os\.(?:remove|unlink)|shutil\.rmtree|unlinkSync|rmSync|Remove-Item)\s*\(?', body, re.I) for body in segment[1:]):
                return '脚本中包含明确的删除调用'
    if has_shell_expansion(command):
        for body in re.findall(r'\$\(([^()]*)\)|`([^`]+)`', command):
            if reason := deletion_reason(body[0] or body[1], depth + 1):
                return reason
    if any(word in lower for word in ('--delete', '--delete-before', '--delete-after', '-delete')):
        return '命令包含删除参数'
    if 'find' in lower and '-exec' in lower:
        start = lower.index('-exec') + 1
        nested = unwrap_command(lower[start:])
        if nested and nested[0].rsplit('/', 1)[-1] in DELETE_PROGRAMS:
            return 'find -exec 中包含明确的删除操作'
    groups = (
        ('kubectl', {'delete', 'replace'}), ('helm', {'uninstall', 'delete'}),
        ('docker', {'rm', 'rmi', 'prune', 'remove'}), ('podman', {'rm', 'rmi', 'prune', 'remove'}),
        ('git', {'clean', 'reset'}),
    )
    for program, verbs in groups:
        if any(segment[0].rsplit('/', 1)[-1] == program and any(verb in segment[1:] for verb in verbs) for segment in commands):
            return '命令包含资源删除或破坏性重置'
    if any(segment[0].rsplit('/', 1)[-1] in ('mysql', 'psql', 'sqlite3', 'sqlcmd') for segment in commands) and any(re.search(r'\b(?:delete\s+from|drop\s+(?:table|database|schema)|truncate\s+table)\b', word, re.I) for word in words):
        return '命令包含删除数据的 SQL'
    return None
