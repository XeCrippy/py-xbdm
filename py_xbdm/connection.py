import socket

from py_xbdm import discovery

from .exceptions import XBDMConnectionError


class XBDMConnection:
    RECV_BUFSIZE = 4096  # Read from socket in 4KB chunks

    def __init__(self, host = None, port=730, timeout=5.0):
        self.host = discovery.xbox_ip() if host is None else host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self._buf = b""  # Internal read buffer

    def connect(self):
        try:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
        except OSError as e:
            raise XBDMConnectionError(str(e))
        self._buf = b""

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        self._buf = b""

    def send(self, data: bytes):
        if not self.sock:
            raise XBDMConnectionError("Not connected")
        self.sock.sendall(data)

    def _fill_buf(self):
        chunk = self.sock.recv(self.RECV_BUFSIZE)
        if not chunk:
            raise XBDMConnectionError("Connection closed")
        self._buf += chunk

    def recv(self, bufsize: int) -> bytes:
        if not self.sock:
            raise XBDMConnectionError("Not connected")
        if self._buf:
            data = self._buf[:bufsize]
            self._buf = self._buf[bufsize:]
            return data
        return self.sock.recv(bufsize)

    def recv_exact(self, size: int) -> bytes:
        while len(self._buf) < size:
            self._fill_buf()
        data = self._buf[:size]
        self._buf = self._buf[size:]
        return data

    def recv_line(self) -> bytes:
        # I can't remember if it's supposed to be \n or '.'
        while b"\n" not in self._buf:
            self._fill_buf()
        idx = self._buf.index(b"\n") + 1
        line = self._buf[:idx]
        self._buf = self._buf[idx:]
        return line
