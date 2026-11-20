"""Best-effort credential filtering for command input and model-visible output."""
import re


PATTERNS = (
    re.compile(r'(?i)(\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|client[_-]?secret|MYSQL_PWD)\b[\s"\x27]*[:=]\s*)(?:"[^"\r\n]*"|\x27[^\x27\r\n]*\x27|[^\s,;]+)'),
    re.compile(r'(?i)(\bAuthorization\s*[:=]\s*["\x27]?(?:Bearer|Basic)\s+)[A-Za-z0-9_+/=.-]+'),
    re.compile(r'(?i)(\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)[^\s/@]+(?=@)'),
    re.compile(r'(?i)(--(?:password|token|api-key)(?:=|\s+))(?:"[^"]*"|\x27[^\x27]*\x27|[^\s;]+)'),
    re.compile(r'(?i)(\bmysql\b[^\r\n]*?\s-p)([^\s"\x27;]+)'),
)
TOKEN = re.compile(r'\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b')
PRIVATE_KEY = re.compile(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|\Z)', re.S)


def redact(text, secrets=()):
    for secret in secrets:
        if secret:
            text = text.replace(secret, '[REDACTED]')
    for pattern in PATTERNS:
        text = pattern.sub(lambda match: match.group(1) + '[REDACTED]', text)
    text = PRIVATE_KEY.sub('[REDACTED PRIVATE KEY]', text)
    return TOKEN.sub('[REDACTED]', text)


def contains_credential(text):
    return redact(text) != text
