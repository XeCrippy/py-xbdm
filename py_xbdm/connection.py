import socket
from .exceptions import XBDMConnectionError


class XBDMConnection:
    def __init__(self, host, port=730, timeout=5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None

    def connect(self):
        try:
            self.sock = socket.create_connection(
                (self.host, self.port), self.timeout
            )
        except OSError as e:
            raise XBDMConnectionError(str(e))

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send(self, data: bytes):
        if not self.sock:
            raise XBDMConnectionError("Not connected")
        self.sock.sendall(data)

    def recv_exact(self, size: int) -> bytes:
        buf = b""
        while len(buf) < size:
            chunk = self.sock.recv(size - len(buf))
            if not chunk:
                raise XBDMConnectionError("Connection closed")
            buf += chunk
        return buf

    def recv_line(self) -> bytes:
        buf = b""
        while not buf.endswith(b"\r\n"):
            chunk = self.sock.recv(1)
            if not chunk:
                raise XBDMConnectionError("Connection closed")
            buf += chunk
        return buf
