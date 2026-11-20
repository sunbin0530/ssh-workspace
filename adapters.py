"""Only the company adapter knows about its post-login OTP/menu protocol."""
from dataclasses import dataclass
import re


def authentication_options(tail):
    """Return the choices actually printed by the bastion at its MFA prompt."""
    menu = re.search(r'请选择多因子认证方式[^\n]*\n(?P<options>.*?)\n\s*>\s*$', tail, re.S)
    if not menu:
        return {}
    return dict(re.findall(r'^\s*\[([A-Za-z0-9]+)\]\s*([^\n]+)', menu['options'], re.M))


@dataclass(frozen=True)
class Adapter:
    name: str
    post_login_mfa: bool
    initial_stage: str


ADAPTERS = {
    'ssh': Adapter('ssh', False, 'shell'),
    'company-bastion': Adapter('company-bastion', True, 'menu'),
}


def get_adapter(name):
    try:
        return ADAPTERS[name]
    except KeyError:
        raise ValueError('Unknown SSH adapter') from None
