import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from command_policy import deletion_reason
from job_state import Jobs
from profiles import ProfileStore
from redaction import redact
from universal_server import SessionConsole


class SecurityTests(unittest.TestCase):
    def test_explicit_deletion_wrappers_and_pathlib(self):
        for command in ('sudo -u app rm /tmp/example', 'sudo --user=app rm /tmp/example',
                        'env -i X=1 rm /tmp/example', 'timeout 30 rm /tmp/example',
                        'python -c \'from pathlib import Path; Path("/tmp/example").unlink()\''):
            self.assertIsNotNone(deletion_reason(command), command)
        self.assertIsNone(deletion_reason('python -c \'print("Path.unlink")\''))

    def test_credentials_are_blocked_before_command_is_stored(self):
        for command in ('mysql -uroot -pExamplePassword -e "select 1"',
                        'curl -H "Authorization: Bearer ExampleToken" https://example.invalid',
                        'MYSQL_PWD=ExamplePassword mysql -e "select 1"'):
            jobs = Jobs()
            with self.assertRaises(ValueError):
                jobs.submit(command)
            self.assertEqual(jobs.items, {})

    def test_split_result_secret_is_held_then_redacted(self):
        jobs = Jobs()
        key = jobs.submit('example')
        jobs.approve(key, True)
        jobs.feed(f'\nSSHOTP_{key}_BEGIN\npassword=Exam')
        self.assertEqual(jobs.read(key)['output'], '')
        jobs.feed(f'pleSecret\nSSHOTP_{key}_END:0\n')
        self.assertNotIn('ExampleSecret', jobs.read(key)['output'])
        self.assertIn('[REDACTED]', jobs.read(key)['output'])
        self.assertNotIn('ExampleSecret', redact('{"password": "ExampleSecret"}'))

    def test_target_change_cancels_pending_approval(self):
        console = SessionConsole.__new__(SessionConsole)
        console.manager = SimpleNamespace(lock=threading.RLock())
        console.prompt_lock = threading.Lock()
        console.browser_prompt = None
        console.stop = threading.Event()
        console.transport = None
        console.channel = SimpleNamespace(closed=False)
        console.auth_stage = 'shell'
        console.target_ready = True
        console.human_active = False
        console.control_revision = 1
        console.jobs = Jobs()
        console.secrets = []
        key = console.jobs.submit('rm /tmp/example')
        console.jobs.items[key]['target_revision'] = 1
        sent = []
        console.execute_job = lambda *args: sent.append(args)
        worker = threading.Thread(target=console.submit_queued_job, args=(key, time.monotonic() + 5))
        worker.start()
        try:
            deadline = time.monotonic() + 2
            while console.prompt_view() is None and time.monotonic() < deadline:
                time.sleep(.01)
            prompt = console.prompt_view()
            self.assertIsNotNone(prompt)
            with console.manager.lock:
                console.invalidate_target()
                console.target_ready = True
            with self.assertRaises(ValueError):
                console.answer_prompt(prompt['id'], True, '')
        finally:
            console.stop.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(sent, [])
        self.assertEqual(console.jobs.read(key)['status'], 'disconnected_outcome_unknown')

    def test_multiple_processes_preserve_all_profiles(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'profiles.json'
            program = ('from profiles import ProfileStore,Profile; import sys; '
                       'ProfileStore(sys.argv[1]).save(Profile(sys.argv[2],sys.argv[2],"192.0.2.1","tester"))')
            workers = [subprocess.Popen([sys.executable, '-c', program, str(path), f'test-{i}'],
                                        cwd=Path(__file__).parent) for i in range(5)]
            for worker in workers:
                self.assertEqual(worker.wait(timeout=15), 0)
            self.assertEqual(len(ProfileStore(path).list()), 5)

    def test_sender_checks_revision_even_when_new_target_is_ready(self):
        console = SessionConsole.__new__(SessionConsole)
        console.manager = SimpleNamespace(lock=threading.RLock())
        console.send_lock = threading.Lock()
        console.stop = threading.Event()
        console.jobs = Jobs()
        console.auth_stage = 'shell'
        console.target_ready = True
        console.human_active = False
        console.control_revision = 2
        sent = []
        console.channel = SimpleNamespace(closed=False, sendall=sent.append)
        key = console.jobs.submit('pwd')
        console.jobs.items[key]['target_revision'] = 1
        wrapped = console.jobs.approve(key, True)
        console.execute_job(key, wrapped)
        self.assertEqual(sent, [])
        self.assertEqual(console.jobs.read(key)['status'], 'disconnected_outcome_unknown')


if __name__ == '__main__':
    unittest.main()
