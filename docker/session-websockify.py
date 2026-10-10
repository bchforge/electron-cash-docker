"""Retain noVNC proxy behavior, adding an explicit intentional close reason."""
import sys
from websockify.websocketproxy import ProxyRequestHandler, websockify_init
from gui_session import enabled, read_state

original_close = ProxyRequestHandler.send_close


def send_close(handler, code=1000, reason=''):
    if enabled():
        state = read_state()
        if state and state[1] == 'ended':
            code, reason = 1000, 'ecd-gui-session-ended'
    return original_close(handler, code, reason)


ProxyRequestHandler.send_close = send_close
if __name__ == '__main__':
    websockify_init()
