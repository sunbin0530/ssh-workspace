"""Bounded job output. Authentication transcript is never an MCP resource."""
import re
import shlex
import threading
import uuid
from command_policy import deletion_reason
from redaction import contains_credential, redact


class Jobs:
    def __init__(self, limit=131072):
        self.lock = threading.RLock()
        self.limit = limit
        self.items = {}
        self.active = None

    def submit(self, command, deletion_summary=None):
        if not command.strip() or len(command) > 8000 or any(ord(c) < 32 for c in command):
            raise ValueError('Use a nonempty single-line command, at most 8000 characters, without control characters')
        if contains_credential(command) or (deletion_summary and contains_credential(deletion_summary)):
            raise ValueError('Inline credentials are not accepted. Use a remote credential file, secret manager or preconfigured environment.')
        with self.lock:
            if self.active:
                raise ValueError('Another job is pending or running; inspect its status first')
            if len(self.items) >= 100:
                raise ValueError('Session job limit reached; start a new connector after reviewing results')
            key = uuid.uuid4().hex
            reason = deletion_summary or deletion_reason(command)
            self.items[key] = dict(job_id=key, command=command, status='queued', approval_reason=reason,
                                   output='', exit_code=None, truncated=False, started=False, scan='')
            self.active = key
            return key

    def approve(self, key, allowed):
        with self.lock:
            job = self.items[key]
            if job['status'] not in ('queued', 'awaiting_user_confirmation'):
                return None
            job['status'] = 'running' if allowed else 'rejected'
            if not allowed:
                self.active = None
                return None
            # Single-line eval preserves current shell/cwd. Markers distinguish output from PTY echo.
            begin, end = 'SSHOTP_' + key + '_BEGIN', 'SSHOTP_' + key + '_END'
            return "printf '\\n%s\\n' " + shlex.quote(begin) + '; eval ' + shlex.quote(job['command']) + "; printf '\\n" + end + ":%s\\n' \"$?\""

    def feed(self, text):
        with self.lock:
            if not self.active:
                return
            job = self.items[self.active]
            if job['status'] != 'running':
                return
            job['scan'] += text.replace('\r', '')
            begin = '\nSSHOTP_' + job['job_id'] + '_BEGIN\n'
            if not job['started']:
                pos = job['scan'].find(begin)
                if pos < 0:
                    job['scan'] = job['scan'][-len(begin):]
                    return
                job['started'] = True
                job['scan'] = job['scan'][pos + len(begin):]
            end = re.search(r'\nSSHOTP_' + job['job_id'] + r'_END:(\d+)\n', job['scan'])
            if end:
                self._append(job, job['scan'][:end.start()])
                job['exit_code'] = int(end.group(1))
                job['status'] = 'completed'
                job['scan'] = ''
                self.active = None
            else:
                # Keep a small suffix for an end marker split across packets.
                keep = 100
                if len(job['scan']) > keep:
                    self._append(job, job['scan'][:-keep])
                    job['scan'] = job['scan'][-keep:]

    def _append(self, job, text):
        space = self.limit - len(job['output'])
        job['output'] += text[:space]
        job['truncated'] |= len(text) > space

    def uncertain(self, key=None):
        with self.lock:
            key = key or self.active
            if key and self.items[key]['status'] in ('running', 'queued', 'awaiting_user_confirmation'):
                self.items[key]['status'] = 'disconnected_outcome_unknown'
            # Do not permit further commands on a desynchronized/disconnected shell.

    def read(self, key, secrets=()):
        with self.lock:
            job = self.items[key]
            result = {k: job[k] for k in ('job_id', 'status', 'output', 'exit_code', 'truncated')}
            # Include buffered output only after a verified BEGIN marker; never include SSH login output.
            if job['started'] and job['status'] == 'running':
                result['output'] = (job['output'] + job['scan'])[:self.limit]
                # Hold the unfinished line so a split credential cannot escape
                # filtering through successive polls.
                result['output'] = result['output'].rsplit('\n', 1)[0] if '\n' in result['output'] else ''
            for secret in secrets:
                if secret:
                    result['output'] = result['output'].replace(secret, '[REDACTED]')
                    # A split echo ending with a secret prefix must not leak via polling.
                    for size in range(1, len(secret)):
                        if result['output'].endswith(secret[:size]):
                            result['output'] = result['output'][:-size] + '[REDACTED]'
                            break
            result['output'] = redact(result['output'], secrets)
            return result
