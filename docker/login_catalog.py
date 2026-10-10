"""Bundled ECD copy, with a safe English fallback independent of catalog files.

Catalog text is data, never markup, paths, format strings or executable code.
"""
from pathlib import Path
import re

KEYS = ('PASSWORD', 'REMEMBER', 'CONNECT', 'INVALID', 'SUBTITLE', 'NOTICE',
        'UNAVAILABLE', 'NOT_FOUND', 'REQUIRED', 'FORBIDDEN', 'BAD_REQUEST',
        'ENDED', 'FOOTER')
ENGLISH: dict[str, str] = dict(zip(KEYS, (
    'Password', 'Remember this session', 'Connect', 'Invalid password.',
    'Bitcoin Cash wallet · Tor-routed SPV',
    'The browser keeps an HTTP session cookie; the server keeps the session record separately from your wallet.',
    'Authentication service unavailable', 'Not found', 'Authentication required',
    'Forbidden', 'Invalid request',
    'Electron Cash GUI session ended. Start Docker Compose again; this tab will recover automatically.',
    'noVNC connects after authentication. The password is never stored in this browser.',
)))


def load_catalogs(path=None):
    result = {'en_us': ENGLISH}
    try:
        lines = Path(path or Path(__file__).with_name('login-translations.tsv')).read_text(encoding='utf-8').splitlines()
        for line in lines:
            if not line or line.startswith('#'):
                continue
            code, *values = line.split('|')
            from login_locale import locale_code
            normalized = locale_code(code)
            if (normalized is None or not re.fullmatch(r'[a-z]{2,3}_[a-z]{2}', normalized)
                    or len(values) != len(KEYS) or any(not value.strip() for value in values)):
                raise ValueError('malformed login catalog')
            if normalized in result and normalized != 'en_us':
                raise ValueError('duplicate login catalog')
            result[normalized] = dict(zip(KEYS, values))
    except (OSError, UnicodeError, ValueError):
        return {'en_us': ENGLISH}
    return result


CATALOGS = load_catalogs()


def resolve(code):
    from login_locale import locale_code
    code = locale_code(code)
    if code in CATALOGS:
        return code
    if code:
        # Only fall back to a language with a bundled, complete catalog.
        same = sorted(c for c in CATALOGS if c.split('_')[0] == code.split('_')[0])
        if same:
            return same[0]
    return 'en_us'


def metadata(code):
    code = resolve(code)
    language, region = code.split('_', 1)
    return language + '-' + region.upper(), 'rtl' if language in ('ar', 'fa') else 'ltr'
