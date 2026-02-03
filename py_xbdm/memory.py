from .protocol import parse_response_line
from .exceptions import XBDMCommandError

def read_memory_text(conn, address: int, length: int) -> bytes:
    cmd = f"getmem addr=0x{address:X} length={length}\r\n"
    conn.send(cmd.encode("ascii"))

    header = conn.recv_line()
    resp = parse_response_line(header)

    if resp.code != 202:
        raise XBDMCommandError(resp.code, resp.message)

    hex_line = conn.recv_line().strip()

    peek = conn.recv_line()
    if peek.strip() != b".":
        pass

    return bytes.fromhex(hex_line.decode("ascii"))

def write_memory(conn, address: int, data: bytes):
    cmd = f"setmem addr=0x{address:X} data={data.hex()}\r\n"
    conn.send(cmd.encode())

    header = conn.recv_line()
    resp = parse_response_line(header)

    if resp.code != 200:
        raise XBDMCommandError(resp.code, resp.message)
