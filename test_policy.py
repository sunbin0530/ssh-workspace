import unittest
from command_policy import deletion_reason


class PolicyTests(unittest.TestCase):
    def test_ordinary_commands_do_not_prompt(self):
        for command in ('pwd', 'ls -la', 'hostname', 'kubectl get nodes -o wide',
                        'kubectl config current-context', 'mkdir -p agent', 'cd /tmp',
                        'git status', 'cat /etc/os-release'):
            self.assertIsNone(deletion_reason(command), command)

    def test_explicit_deletion_requires_confirmation(self):
        for command in ('rm -rf /tmp/example', 'sudo /bin/rm example',
                        'kubectl delete pod example', 'helm uninstall example',
                        'find /tmp -delete', 'git clean -fd', 'rsync --delete a b',
                        "bash -c 'rm example'", "python -c 'import os; os.remove(\"example\")'",
                        'echo $(rm example)', 'env rm example'):
            self.assertIsNotNone(deletion_reason(command), command)

    def test_indirection_and_quoted_search_terms_do_not_request_user_risk_assessment(self):
        for command in ("python -c 'import os'", './cleanup.sh', 'echo $(hostname)',
                        "bash -c 'ls -la'", "find /tmp -exec stat {} \\;",
                        "grep -F 'rm' app.log", "grep -F 'DROP TABLE sample' app.log"):
            self.assertIsNone(deletion_reason(command), command)

    def test_literal_backticks_in_log_filter_are_not_execution(self):
        self.assertIsNone(deletion_reason("kubectl logs pod --previous | grep -F 'CREATE TABLE `rest_catalog`.`iceberg_ods`.`dataset`'"))
        self.assertIsNone(deletion_reason("grep -F '$(literal)' file"))
        self.assertIsNotNone(deletion_reason('echo "$(rm example)"'))
        self.assertIsNotNone(deletion_reason('echo "`rm example`"'))


if __name__ == '__main__':
    unittest.main()
