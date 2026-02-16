from .protocol import parse_response_line
from .exceptions import XBDMCommandError

def read_memory_text(conn, address: int, length: int) -> bytes:
    cmd = f"getmem addr=0x{address:X} length={length}\r\n"
    conn.send(cmd.encode("ascii"))

    header = conn.recv_line()
    resp = parse_response_line(header)

    if resp.code != 202:
        raise XBDMCommandError(resp.code, resp.message)

    # Console may split hex data across multiple lines; read until "." terminator
    hex_parts = []
    while True:
        line = conn.recv_line().strip()
        if line == b".":
            break
        hex_parts.append(line.decode("ascii"))

    return bytes.fromhex("".join(hex_parts))

def write_memory(conn, address: int, data: bytes):
    cmd = f"setmem addr=0x{address:X} data={data.hex()}\r\n"
    conn.send(cmd.encode())

    header = conn.recv_line()
    resp = parse_response_line(header)

    if resp.code != 200:
        raise XBDMCommandError(resp.code, resp.message)
