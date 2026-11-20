"""Opt-in menu sharing; a renewed authentication prompt revokes sharing."""
import re
import threading

AUTH_PROMPT = re.compile(r'(?:password|passphrase|请输入[^\n]*(?:OTP|动态码|验证码|口令|密码)|enter[^\n]*(?:OTP|token))[^\n]{0,40}[:：]\s*$', re.I)
MENU_TOKEN = re.compile(r'[A-Za-z0-9_.:@/\-]{1,200}')
SEARCH_PROMPT = re.compile(r'输入搜索关键字\s*[:：]\s*$')
ASSET_COMMANDS = re.compile(r'^[ \t]*(?:操作命令|(?:Operation )?Commands)[ \t]*[:：][ \t]*$', re.I | re.M)


def asset_menu_text(tail):
    """Recognize the command list at the live bastion prompt, not a lone >."""
    if not re.search(r'(?:^|\n)[ \t]*>[ \t\n]*$', tail):
        return ''
    matches = list(ASSET_COMMANDS.finditer(tail))
    if not matches:
        return ''
    menu = tail[matches[-1].start():]
    if re.search(r'^[ \t]*\[l\][ \t]', menu, re.M) and re.search(r'^[ \t]*\[s\][ \t]', menu, re.M):
        return menu
    return ''


def is_immediate_menu_key(text, tail):
    # Observed bastion: `s` immediately opens a line editor. An extra CR cancels it.
    return text == 's' and bool(re.search(r'>\s*$', tail)) and '[s]' in tail and not SEARCH_PROMPT.search(tail)


class BastionView:
    def __init__(self):
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        with self.lock:
            self.shared = False
            self.candidate = ''
            self.output = ''
            self.tail = ''
            self.revision = 0

    def feed(self, text, eligible):
        with self.lock:
            self.tail = (self.tail + text)[-2000:]
            if AUTH_PROMPT.search(self.tail):
                self.shared = False
                self.candidate = ''
                self.output = ''
                return
            if not eligible:
                return
            self.candidate = (self.candidate + text)[-32768:]
            if self.shared:
                self.output = (self.output + text)[-32768:]
                self.revision += 1

    def grant(self, reviewed_text):
        with self.lock:
            self.shared = True
            self.output = reviewed_text[-32768:]
            self.revision += 1

    def read(self, secrets):
        with self.lock:
            text = self.output if self.shared else ''
            for secret in secrets:
                if secret:
                    text = text.replace(secret, '[REDACTED]')
                    for size in range(1, len(secret)):
                        if text.endswith(secret[:size]):
                            text = text[:-size] + '[REDACTED]'
                            break
            return {'shared': self.shared, 'revision': self.revision, 'output': text,
                    'note': 'Bounded asset-menu transcript; terminal controls are not fully emulated. Follow observed menu syntax only.'}
