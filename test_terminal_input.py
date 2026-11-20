"""Offline regression checks; no network or real credentials."""
import threading
import time
import unittest

from ssh_otp import OTP_PROMPT, send_terminal_line
from adapters import authentication_options


class LegacyInputTests(unittest.TestCase):
    def test_takeover_aborts_agent_line_before_enter(self):
        packets = []
        class Channel:
            def sendall(self, value):
                packets.append(value)
        with self.assertRaises(RuntimeError):
            send_terminal_line(Channel(), 'abc', threading.Event(), pause=0, abort_if=lambda: len(packets)>0)
        self.assertEqual(packets, [b'a'])
    def test_menu_choice_arrives_before_enter(self):
        received = []

        class Channel:
            def sendall(self, data):
                received.append((time.monotonic(), data))

        send_terminal_line(Channel(), '1', threading.Event())
        self.assertEqual([item[1] for item in received], [b'1', b'\r'])
        self.assertGreaterEqual(received[1][0] - received[0][0], .2)

    def test_otp_not_submitted_as_paste(self):
        packets = []

        class Channel:
            def sendall(self, data):
                packets.append(data)

        send_terminal_line(Channel(), '123456', threading.Event(), pause=0)
        self.assertTrue(all(len(packet) == 1 for packet in packets))
        self.assertEqual(b''.join(packets), b'123456\r')

    def test_menu_does_not_open_otp_dialog(self):
        self.assertIsNone(OTP_PROMPT.search('请选择多因子认证方式:\n [1] 手机令牌OTP\n> '))
        self.assertIsNotNone(OTP_PROMPT.search('请输入手机令牌OTP: '))

    def test_authentication_options_follow_server_menu(self):
        menu = '请选择多因子认证方式：\n  [2] 手机令牌\n  [3] 短信验证码\n  [a] 其他验证\n> '
        self.assertEqual(authentication_options(menu), {'2': '手机令牌', '3': '短信验证码', 'a': '其他验证'})
        self.assertEqual(authentication_options(menu[:-2]), {})
        self.assertEqual(authentication_options('操作命令：\n [s] 搜索资源\n> '), {})
        self.assertIsNotNone(OTP_PROMPT.search('请输入短信验证码： '))

    def test_cancel_sends_nothing(self):
        stop = threading.Event()
        stop.set()

        class Channel:
            def sendall(self, data):
                raise AssertionError('Cancelled input must not reach remote host')

        with self.assertRaises(RuntimeError):
            send_terminal_line(Channel(), '1', stop)


if __name__ == '__main__':
    unittest.main()
