import unittest
from job_state import Jobs


class JobTests(unittest.TestCase):
    def test_requires_approval_and_discards_login_transcript(self):
        jobs = Jobs()
        key = jobs.submit('hostname')
        jobs.feed('Password: secret\nOTP: 123456\n')
        self.assertEqual(jobs.read(key)['output'], '')
        self.assertIsNone(jobs.approve(key, False))
        self.assertEqual(jobs.read(key)['status'], 'rejected')

    def test_agent_identified_deletion_is_queued_with_a_concrete_reason(self):
        jobs = Jobs()
        key = jobs.submit('./cleanup.sh', '删除 /tmp/old-report 中的过期报告')
        self.assertEqual(jobs.read(key)['status'], 'queued')
        self.assertEqual(jobs.items[key]['approval_reason'], '删除 /tmp/old-report 中的过期报告')

    def test_fragmented_markers_and_exit_status(self):
        jobs = Jobs()
        key = jobs.submit('hostname')
        wrapper = jobs.approve(key, True)
        stream = wrapper + '\r\n' + '\nSSHOTP_' + key + '_BEGIN\nnode-a\nSSHOTP_' + key + '_END:7\n'
        for char in stream:
            jobs.feed(char)
        result = jobs.read(key)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['output'], 'node-a')
        self.assertEqual(result['exit_code'], 7)
        self.assertIsNone(jobs.active)

    def test_bounded_output_and_secret_redaction(self):
        jobs = Jobs(limit=100)
        key = jobs.submit('example')
        jobs.approve(key, True)
        jobs.feed('\nSSHOTP_' + key + '_BEGIN\n' + 'secret' + 'x' * 2000)
        jobs.feed('\nSSHOTP_' + key + '_END:0\n')
        result = jobs.read(key, ['secret'])
        self.assertNotIn('secret', result['output'])
        self.assertTrue(result['truncated'])

    def test_unknown_outcome_blocks_resubmission(self):
        jobs = Jobs()
        key = jobs.submit('example')
        jobs.approve(key, True)
        jobs.uncertain()
        self.assertEqual(jobs.read(key)['status'], 'disconnected_outcome_unknown')
        with self.assertRaises(ValueError):
            jobs.submit('example')

    def test_rejects_multiline_and_terminal_controls(self):
        for text in ('', 'echo a\necho b', 'abc\x03'):
            with self.assertRaises(ValueError):
                Jobs().submit(text)


if __name__ == '__main__':
    unittest.main()
