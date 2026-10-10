"""The native Qt startup theme; no periodic overrides or browser styling."""
import os


def theme_from_environment(environment=None):
    environment = os.environ if environment is None else environment
    value = environment.get('DARK_MODE', '').strip().lower() or 'false'
    if value not in ('true', 'false'):
        raise ValueError('DARK_MODE must be true or false (missing/empty selects light)')
    return 'dark' if value == 'true' else 'default'
