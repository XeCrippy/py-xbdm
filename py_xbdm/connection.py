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

    @property
    def is_connected(self) -> bool:
        """Return True if the socket appears to be open."""
        if self.sock is None:
            return False
        try:
            # Peek with zero timeout to detect a closed/reset socket
            self.sock.setblocking(False)
            try:
                data = self.sock.recv(1, socket.MSG_PEEK)
                if data == b"":
                    return False          # peer closed gracefully
            except BlockingIOError:
                pass                      # no data ready – socket still alive
            except (OSError, ConnectionError):
                return False
            finally:
                self.sock.setblocking(True)
                self.sock.settimeout(self.timeout)
            return True
        except Exception:
            return False

    def connect(self):
        try:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
        except OSError as e:
            raise XBDMConnectionError(str(e))
        self._buf = b""

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
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
