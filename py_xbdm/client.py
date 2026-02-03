import struct
from .connection import XBDMConnection
from .protocol import parse_response_line
from .memory import read_memory_text, write_memory

class XBDMClient:
    
    VOID        = 0
    INT         = 1
    FLOAT       = 3
    BYTE        = 4
    STRING      = 2
    UINT64      = 8

    INT_ARRAY   = 5
    FLOAT_ARRAY = 6
    BYTE_ARRAY  = 7
    UINT64_ARRAY= 9

    def __init__(self, host):
        self.conn = XBDMConnection(host)

    def __enter__(self):
        self.conn.connect()
        banner = self.conn.recv_line()
        parse_response_line(banner)

        return self

    def __exit__(self, exc_type, exc, tb):
        self.conn.close()

    # Call a function that returns an integer
    # Usage: result = xbdm.call_int(addr, [0, "string_param", 1.0])
    def call_int(self, address: int, args, system_thread: bool = True) -> int:
        result = self.call_function(address, args, return_type=self.INT, system_thread=system_thread)
        return int(result, 16)

    # Call a function with any return type
    # usage: u64_value = xbdm.call_function(addr, [0, "str_param", 1.0], xbdm.UINT64)
    def call_function(self, address: int, args, return_type: any = INT, system_thread: bool = True):
        cmd = []
        cmd.append("consolefeatures ver=2")
        cmd.append(f"type={return_type}")
        if system_thread:
            cmd.append("system")

        params = []
        params.append(f"A\\{address:X}\\A\\{len(args)}\\")

        for arg in args:
            params.append(self.encode_argument(arg))

        param_str = "".join(params)
        full_cmd = " ".join(cmd) + f' as=0 params="{param_str}"'

        response = self.send_command(full_cmd)

        while "buf_addr=" in response.message:
            buf = response.message.split("buf_addr=")[1][:8]
            response = self.send_command(f"consolefeatures buf_addr=0x{buf}")

        return response.message.strip()

    def call_void(self, address: int, args, system_thread: bool = True):
        self.call_function(address, args, return_type=self.VOID, system_thread=system_thread)

    def console_name(self) -> str:
        resp = self.send_command("dbgname")
        return resp.message.strip()
    
    def encode_argument(self, arg):
        if isinstance(arg, int):
            return f"{self.INT}\\{arg}\\"

        if isinstance(arg, float):
            return f"{self.FLOAT}\\{arg}\\"

        if isinstance(arg, str):
            raw = arg.encode("ascii")
            hexstr = raw.hex().upper()
            return f"{self.BYTE_ARRAY}/{len(raw)}\\{hexstr}\\"

        if isinstance(arg, (bytes, bytearray)):
            hexstr = arg.hex().upper()
            return f"{self.BYTE_ARRAY}/{len(arg)}\\{hexstr}\\"

        raise TypeError(f"Unsupported argument type: {type(arg)}")

    def get_console_id(self) -> str:
        cmd = f"getconsoleid"
        resp = self.send_command(cmd)
        if resp.message.startswith(" consoleid="):
            resp.message = resp.message[len(" consoleid="):]
        return resp.message.strip()
    
    def get_console_type(self) -> str:
        cmd = f"consolefeatures ver=2 type=17 params=\"A\\0\\A\\0\\\""; 
        resp = self.send_command(cmd)
        return resp.message.strip()
    
    def get_current_title_id(self) -> str:
        cmd = f"consolefeatures ver=2 type=16 params=\"A\\0\\A\\0\\\""
        resp = self.send_command(cmd)
        return resp.message.strip()
    
    def get_cpukey(self) -> bytes:
        cmd = f"consolefeatures ver=2 type=10 params=\"A\\0\\A\\0\\\""; 
        resp = self.send_command(cmd)
        return bytes.fromhex(resp.message)
    
    def get_kernel_version(self) -> str:
        cmd = f"consolefeatures ver=2 type=13 params=\"A\\0\\A\\0\\\""
        resp = self.send_command(cmd)
        return resp.message.strip()
    
    def load_module(self, module_path: str) -> int:
        addr = self.resolve_function("xboxkrnl.exe", 409)
        result = self.call_int(addr, [module_path, 8, 0, 0])
        return result
 
    def parse_return(response, return_type):
        try:
            _, value = response.split(" ", 1)
            value = value.strip()
        except ValueError:
            raise RuntimeError("Malformed response")

        if return_type is int:
            return int(value, 16)

        if return_type is float:
            return float(value)

        if return_type is str:
            return value

        if return_type is type(None):
            return None
        
        if return_type is 8:
            return int(value, 16)
        
        raise TypeError("Unsupported return type")

    def read_memory(self, address: int, size: int) -> bytes:
        resp = read_memory_text(self.conn, address, size)
        return resp

    def read_float(self, address: int) -> float:
        raw = read_memory_text(self.conn, address, 4)
        return struct.unpack('<f', raw)[0]

    def read_double(self, address: int) -> float:
        raw = read_memory_text(self.conn, address, 8)
        return struct.unpack('<d', raw)[0]
        
    def read_u16(self, address: int) -> int:
        raw = read_memory_text(self.conn, address, 2)
        return int.from_bytes(raw, "big")
    
    def read_u32(self, address: int) -> int:
        raw = read_memory_text(self.conn, address, 4)
        return int.from_bytes(raw, "big")

    def read_u64(self, address: int) -> int:
        raw = read_memory_text(self.conn, address, 8)
        return int.from_bytes(raw, "big")

    def read_cstring(self, address: int, max_length: int = 256) -> str:
        data = bytearray()
        for i in range(max_length):
            byte = self.read_memory(address + i, 1)
            if byte[0] == 0:
                break
            data.append(byte[0])
        return data.decode('utf-8')

    # Reaolve a function address at a specified ordinal within a specified module
    # addr = xbdm.resolve_functiom("xam.xex", 0x1FC)
    def resolve_function(self, module_name: str, ordinal: int) -> int:
        hex_module = ''.join(f"{ord(c):02X}" for c in module_name)

        cmd = f'consolefeatures ver=2 type=9 params="A\\0\\A\\2\\{self.BYTE_ARRAY}/{len(hex_module)//2}\\{hex_module}\\{self.INT}\\{ordinal}\\"'
        resp = self.send_command(cmd)
        return int(resp.message.strip(), 16)
    
    def send_command(self, command: str):
        self.conn.send(command.encode() + b"\r\n")
        line = self.conn.recv_line()
        return parse_response_line(line)
    
    def unload_module(self, module: str):
        address = self.resolve_function("xam.xex", 1102)
        handle = self.call_int(address, [module])
        if handle != 0:
            self.write_uint16(handle + 0x40, 1)
            addr_unload = self.resolve_function("xboxkrnl.exe", 417)
            self.call_int(addr_unload, [handle])
    
    def write_double(self, address: int, value: float):
        data = struct.pack('<d', value)
        data = data[::-1]
        write_memory(self.conn, address, data)

    def write_float(self, address: int, value: float):
        data = struct.pack('<f', value)
        data = data[::-1]
        write_memory(self.conn, address, data)

    # PatchInJump
    def write_hook(self, address: int, destination: int, linked: bool):
        func = [0, 0, 0, 0]
        if (destination & 0x8000) != 0:
            func[0] = 0x3D600000 + (((destination >> 16) & 0xFFFF) + 1)
        else:
            func[0] = 0x3D600000 + ((destination >> 16) & 0xFFFF)
            func[1] = 0x396B0000 + (destination & 0xFFFF)
            func[2] = 0x7D6903A6
            func[3] = 0x4E800420
        if linked:
            func[3] += 1

        buffer = bytearray(16)
        for i in range(4):
            part = func[i].to_bytes(4, 'big')
            buffer[i*4:(i+1)*4] = part

        self.write_memory(address, buffer)

    def write_memory(self, address: int, data: bytes):
        write_memory(self.conn, address, data)

    def write_string(self, address: int, string: str):
        data = string.encode('utf-8')
        write_memory(self.conn, address, data)

    def write_uint16(self, address: int, value: int):
        write_memory(self.conn, address, value.to_bytes(2, 'big'))

    def write_uint32(self, address: int, value: int):
        write_memory(self.conn, address, value.to_bytes(4, 'big'))

    def write_uint64(self, address: int, value: int):
        write_memory(self.conn, address, value.to_bytes(8, 'big'))

    def write_wstring(self, address: int, string: str):
        data = string.encode('utf-16le')
        write_memory(self.conn, address, data)

    def xnotify(self, text: str, type: int = 34) -> None:
        cmd = f'consolefeatures ver=2 type=12 params="A\\0\\A\\2\\{self.BYTE_ARRAY}/{len(text)}\\{text.encode("ascii").hex().upper()}\\{self.INT}\\{type}\\"'
        self.send_command(cmd)

