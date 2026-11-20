"""Non-secret connection profiles. No password, OTP, or private-key contents."""
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import threading
import os
import tempfile
import time
from contextlib import contextmanager


@contextmanager
def profile_file_lock(path):
    with open(path, 'a+b') as lock_file:
        lock_file.seek(0, 2)
        if lock_file.tell() == 0:
            lock_file.write(b'0')
            lock_file.flush()
        deadline = time.monotonic() + 10
        while True:
            try:
                lock_file.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    raise TimeoutError('Connection profiles are busy')
                time.sleep(.05)
        try:
            yield
        finally:
            lock_file.seek(0)
            if os.name == 'nt':
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)



@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    host: str
    username: str
    port: int = 22
    adapter: str = 'ssh'
    fingerprint: str = ''
    private_key_path: str = ''

    @classmethod
    def parse(cls, value):
        if set(value) - set(cls.__dataclass_fields__):
            raise ValueError('Profile contains unsupported fields; credentials must not be saved')
        profile = cls(**value)
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', profile.id):
            raise ValueError('Profile id must contain letters, digits, _ or -')
        if not profile.name.strip() or not profile.username.strip() or not profile.host.strip():
            raise ValueError('Name, username and host are required')
        if any(c.isspace() for c in profile.host) or len(profile.host) > 253:
            raise ValueError('Invalid host')
        if not isinstance(profile.port, int) or isinstance(profile.port, bool) or not 1 <= profile.port <= 65535:
            raise ValueError('Invalid port')
        if profile.adapter not in ('ssh', 'company-bastion'):
            raise ValueError('Unsupported adapter')
        if profile.fingerprint and not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', profile.fingerprint):
            raise ValueError('Expected SHA256 host-key fingerprint')
        for value in asdict(profile).values():
            if isinstance(value, str) and (len(value) > 2048 or any(ord(c) < 32 for c in value)):
                raise ValueError('Profile values cannot contain control characters')
        return profile




class ProfileStore:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()

    def list(self):
        with self.lock:
            if not self.path.exists():
                return []
            with profile_file_lock(self.path.with_suffix('.lock')):
                return self._list_unlocked()

    def _list_unlocked(self):
        if not self.path.exists():
            return []
        records = json.loads(self.path.read_text(encoding='utf-8'))
        profiles = [Profile.parse(record) for record in records]
        if len({profile.id for profile in profiles}) != len(profiles):
            raise ValueError('Duplicate profile ids')
        return profiles

    def get(self, key):
        for profile in self.list():
            if profile.id == key:
                return profile
        raise ValueError('Unknown connection profile')

    def save(self, profile):
        profile = Profile.parse(asdict(profile))
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with profile_file_lock(self.path.with_suffix('.lock')):
                records = {item.id: item for item in self._list_unlocked()}
                records[profile.id] = profile
                with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.path.parent,
                                                 prefix='.profiles-', delete=False) as output:
                    temporary = Path(output.name)
                    json.dump([asdict(item) for item in records.values()], output, ensure_ascii=False, indent=2)
                    output.flush()
                    os.fsync(output.fileno())
                try:
                    os.replace(temporary, self.path)
                finally:
                    if temporary.exists():
                        temporary.unlink()

