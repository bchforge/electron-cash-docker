"""Locale-only bridge; the auth service never needs the Electron Cash config."""
import os
import re
import stat
import tempfile
from functools import wraps
from pathlib import Path
from contextlib import nullcontext

LOCALE_FILE = Path('/run/ecd-gui-session/login-language')


def locale_code(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    # Accept conventional gettext/BCP47 spellings, never arbitrary config text.
    value = value.strip().split('.', 1)[0].split('@', 1)[0].replace('-', '_').lower()
    return value if re.fullmatch(r'[a-z]{2,3}(?:_[a-z0-9]{2,8})*', value) else None


def login_language(path=None, environment=None):
    """Published selection beats startup defaults; browser headers are irrelevant."""
    path = Path(path) if path is not None else LOCALE_FILE
    environment = os.environ if environment is None else environment
    code = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if stat.S_ISREG(info.st_mode) and info.st_size <= 65:
                code = locale_code(handle.read(66).decode('ascii').strip())
    except (OSError, UnicodeError):
        pass
    if code is None:
        code = locale_code(environment.get('EC_LANGUAGE', 'en_US'))
    # A valid but untranslated explicit selection must NOT inherit Spanish
    # from an environment/browser default. Metadata describes rendered copy.
    from login_catalog import resolve
    return resolve(code)


def publish_language(config, *, path=None, system_language=None):
    """Read only the effective language key, not the private configuration file."""
    if os.environ.get('ECD_GUI_SESSION', 'false') != 'true':
        return
    path = Path(path) if path is not None else LOCALE_FILE
    if system_language is None:
        from electroncash.i18n import get_system_language_match
        system_language = get_system_language_match
    code = locale_code(config.get('language') or system_language()) or 'en_us'
    name = None
    try:
        if path.parent.is_symlink() or not path.parent.is_dir() or path.is_symlink():
            raise OSError('unsafe locale state path')
        fd, name = tempfile.mkstemp(prefix='.login-language-', dir=path.parent)
        with os.fdopen(fd, 'w', encoding='ascii') as handle:
            handle.write(code + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, 0o644)
        os.replace(name, path)
    except OSError:
        # Localization must not interrupt config saving or authentication.
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        print('[!] Login locale publication unavailable', flush=True)
    finally:
        if name is not None:
            try:
                Path(name).unlink(missing_ok=True)
            except OSError:
                pass


def install_language_bridge(config_class=None, publisher=publish_language):
    if config_class is None:
        from electroncash.simple_config import SimpleConfig
        config_class = SimpleConfig
    if getattr(config_class, '_docker_login_locale', False):
        return
    original_init, original_set_key = config_class.__init__, config_class.set_key

    @wraps(original_init)
    def init(config, *args, **kwargs):
        original_init(config, *args, **kwargs)
        publisher(config)

    @wraps(original_set_key)
    def set_key(config, key, value, *args, **kwargs):
        # Serialize config save + publication under upstream's reentrant lock,
        # so a delayed publisher cannot replace a newer Settings selection.
        with getattr(config, 'lock', nullcontext()):
            result = original_set_key(config, key, value, *args, **kwargs)
            if key == 'language':
                publisher(config)
            return result

    config_class.__init__, config_class.set_key = init, set_key
    config_class._docker_login_locale = True
