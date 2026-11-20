import unittest

from bastion_state import BastionView, MENU_TOKEN, is_immediate_menu_key


class BastionTests(unittest.TestCase):
    def test_search_key_has_no_implicit_enter(self):
        menu = '操作命令:\n  [s] 搜索资源，根据IP/name/account/label\n> '
        self.assertTrue(is_immediate_menu_key('s', menu))
        self.assertFalse(is_immediate_menu_key('80.2', menu + '\n输入搜索关键字: '))
        self.assertFalse(is_immediate_menu_key('s', menu + '\n输入搜索关键字: '))
        self.assertFalse(is_immediate_menu_key('s', 'user@host:~$ '))

    def test_authentication_transcript_is_private(self):
        view = BastionView()
        view.feed('Password: example\n', eligible=False)
        self.assertEqual(view.read([])['output'], '')
        view.feed('资产菜单\n输入编号 > ', eligible=True)
        self.assertEqual(view.read([])['output'], '')
        view.grant('资产菜单\n输入编号 > ')
        view.feed('node-a\n', eligible=True)
        self.assertEqual(view.read([])['output'], '资产菜单\n输入编号 > node-a\n')

    def test_fragmented_new_otp_revokes_sharing(self):
        view = BastionView()
        view.grant('资产菜单')
        view.feed('请输入手机令牌', eligible=True)
        view.feed('OTP:', eligible=True)
        self.assertFalse(view.read([])['shared'])
        self.assertEqual(view.read([])['output'], '')
        view.feed('123456', eligible=False)
        self.assertEqual(view.read([])['output'], '')

    def test_reconnect_revokes_consent_and_output(self):
        view = BastionView()
        view.grant('menu')
        view.reset()
        self.assertFalse(view.shared)
        self.assertEqual(view.read([])['output'], '')

    def test_single_token_only(self):
        for text in ('10.1.2.3', 'node-a', '1', '/node-a'):
            self.assertIsNotNone(MENU_TOKEN.fullmatch(text))
        for text in ('rm -rf /', '1;id', '$(id)', '1\r', 'a\nb'):
            self.assertIsNone(MENU_TOKEN.fullmatch(text))

    def test_redacts_fragmented_secret_and_caps_buffer(self):
        view = BastionView()
        view.grant('menu\n123')
        self.assertNotIn('123', view.read(['123456'])['output'])
        view.feed('456', eligible=True)
        self.assertNotIn('123456', view.read(['123456'])['output'])
        view.feed('x' * 100000, eligible=True)
        self.assertLessEqual(len(view.output), 32768)


if __name__ == '__main__':
    unittest.main()
