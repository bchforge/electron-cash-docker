/* Terminal GUI generations stop RFB; one passive observer detects later startup. */
(() => {
    let terminal = false;
    let generation = null;
    let unavailable = false;
    let navigating = false;
    let destroyed = false;
    let timer = null;
    let controller = null;
    let backoff = 5000;
    const NativeWebSocket = window.WebSocket;
    const protectedPage = '/vnc.html?autoconnect=true&reconnect=true&reconnect_delay=3000';
    const ui = () => import('/app/ui.js').then(module => module.default);
    let endedNotice = 'Electron Cash GUI session ended. Start Docker Compose again; this tab will recover automatically.';

    async function stopRfb() {
        const UI = await ui();
        UI.inhibitReconnect = true;
        UI.cancelReconnect();
        if (UI.rfb) UI.rfb.disconnect();
        UI.connected = false;
        UI.updateVisualState('disconnected');
        return UI;
    }
    async function endSession() {
        if (terminal || navigating || destroyed) return;
        terminal = true;
        window.ecdGuiSessionEnded = true;
        window.ecdGuiRecoveryState = 'ended';
        const UI = await stopRfb();
        UI.showStatus(endedNotice, 'normal');
    }
    async function navigate(target, state) {
        if (navigating || destroyed) return;
        navigating = true;
        clearTimeout(timer);
        window.ecdGuiRecoveryState = state;
        try { await stopRfb(); }
        finally { if (!destroyed) location.replace(target); }
    }
    window.WebSocket = new Proxy(NativeWebSocket, {
        construct(target, args, newTarget) {
            const socket = Reflect.construct(target, args, newTarget);
            if (new URL(socket.url, location.href).pathname === '/websockify') {
                socket.addEventListener('close', event => {
                    if (event.code === 1000 && event.reason === 'ecd-gui-session-ended') endSession();
                }, {once: true});
            }
            return socket;
        },
    });
    function schedule(delay) {
        clearTimeout(timer);
        if (!destroyed && !navigating) timer = setTimeout(observe, delay);
    }
    async function observe() {
        if (controller || destroyed || navigating) return;
        controller = new AbortController();
        const timeout = setTimeout(() => controller?.abort(), 3000);
        let delay = terminal ? 5000 : 1000;
        try {
            const response = await fetch('/auth/gui-session', {
                credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
            });
            if (response.status === 401) {
                await navigate('/', 'login');
                return;
            }
            if (!response.ok) throw new Error('service not ready');
            const state = await response.json();
            if (typeof state.lang === 'string' && /^[a-z]{2,3}-[A-Z]{2}$/.test(state.lang) &&
                ['ltr', 'rtl'].includes(state.dir) && state.copy && typeof state.copy.ENDED === 'string') {
                document.documentElement.lang = state.lang;
                document.documentElement.dir = state.dir;
                endedNotice = state.copy.ENDED;
                for (const element of document.querySelectorAll('[data-ecd-copy]')) {
                    const value = state.copy[element.dataset.ecdCopy];
                    if (typeof value === 'string') element.textContent = value;
                }
                if (terminal) (await ui()).showStatus(endedNotice, 'normal');
            }
            if (!['active', 'ended', 'unavailable'].includes(state.state) ||
                (state.state !== 'unavailable' && !/^[0-9a-f]{32}$/.test(state.generation)) ||
                typeof state.ready !== 'boolean') throw new Error('invalid status');
            backoff = 5000;
            if (state.state === 'ended') {
                generation = state.generation;
                await endSession();
            } else if (state.state === 'active') {
                if (terminal) {
                    if ((generation && state.generation !== generation) || (!generation && unavailable)) {
                        window.ecdGuiRecoveryState = 'starting';
                        if (state.ready) await navigate(protectedPage, 'recovering');
                    }
                } else {
                    generation = state.generation;
                    window.ecdGuiGeneration = generation;
                    window.ecdGuiRecoveryState = state.ready ? 'connected' : 'starting';
                }
            }
            delay = terminal ? 5000 : 1000;
        } catch (_error) {
            // Network/5xx/403/malformed status cannot prove invalid authentication.
            unavailable = true;
            window.ecdGuiRecoveryState = terminal ? 'offline-ended' : 'offline';
            delay = backoff;
            backoff = Math.min(backoff * 2, 30000);
        } finally {
            clearTimeout(timeout);
            controller = null;
            schedule(delay);
        }
    }
    function wake() { if (!controller) schedule(0); }
    function cleanup() {
        destroyed = true;
        clearTimeout(timer);
        controller?.abort();
        window.removeEventListener('online', wake);
        document.removeEventListener('visibilitychange', wake);
    }
    window.addEventListener('online', wake);
    document.addEventListener('visibilitychange', wake);
    window.addEventListener('pagehide', cleanup, {once: true});
    schedule(0);
})();
