/* Keep intermediaries that ignore WebSocket control frames seeing data. */
(() => {
    const interval = 10000;
    const NativeWebSocket = window.WebSocket;
    const sockets = new Set();

    const isWebsockify = (socket) => {
        try {
            return new URL(socket.url, window.location.href).pathname === "/websockify";
        } catch (_error) {
            return false;
        }
    };

    window.WebSocket = new Proxy(NativeWebSocket, {
        construct(target, args, newTarget) {
            const socket = Reflect.construct(target, args, newTarget);
            if (isWebsockify(socket)) {
                sockets.add(socket);
                socket.addEventListener("close", () => sockets.delete(socket), { once: true });
            }
            return socket;
        },
    });

    window.setInterval(() => {
        for (const socket of sockets) {
            if (socket.readyState !== NativeWebSocket.OPEN) {
                sockets.delete(socket);
                continue;
            }
            try {
                // websockify forwards this as a zero-byte VNC write.
                socket.send(new Uint8Array(0));
            } catch (_error) {
                sockets.delete(socket);
            }
        }
    }, interval);
})();
