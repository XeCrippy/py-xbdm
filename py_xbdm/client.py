# Internal imports
import os
import re
import struct
import tempfile
import time
from typing import Optional

# Third-party imports
import numpy as np
from PIL import Image

# Local imports
from py_xbdm import discovery
from py_xbdm.connection import XBDMConnection
from py_xbdm.protocol import parse_response_line
from py_xbdm.memory import read_memory_text, write_memory


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

    def __init__(self, host=discovery.xbox_ip()):
        self.conn = XBDMConnection(host)

    def __enter__(self):
        self.conn.connect()
        banner = self.conn.recv_line()
        parse_response_line(banner)

        return self

    def __exit__(self, exc_type, exc, tb):
        self.send_command("bye")
        self.conn.close()

    def close(self):
        self.send_command("bye")
        self.conn.close()

    def reconnect(self, host=discovery.xbox_ip()):
        self.conn.close()
        self.conn = XBDMConnection(host)
        self.conn.connect()
        banner = self.conn.recv_line()
        parse_response_line(banner)

        return self

    # Call a function that returns an integer
    def call_int(self, address: int, args, system_thread: bool = True) -> int:
        result = self.call_function(address, args, return_type=self.INT, system_thread=system_thread)
        return int(result, 16)
    
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

    def call_void(self, address: int, args=[None], system_thread: bool = True):
        self.call_function(address, args, return_type=self.VOID, system_thread=system_thread)

    def console_name(self) -> str:
        resp = self.send_command("dbgname")
        return resp.message.strip()


    def create_directory(self, remotePath: str) -> bool:
        command = "mkdir name=\"" + remotePath + "\""
        response = self.send_command(command)
        if response.code != 410:
            return True
        elif response.code == 200:
            return False
        return True
    
    
    def debug_go(self):
        self.send_command("go")


    def debug_stop(self):
        self.send_command("stop")


    def delete_file(self, remote_path: str, is_directory: bool = False):
        cmd = f'delete name="{remote_path}"' + (" dir" if is_directory else "")
        resp = self.send_command(cmd)
        if not resp.code == 200:
            raise RuntimeError(f"Couldn't delete {remote_path}")
        
    
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
    
    
    def timet_to_filetime(self, unix_time: int) -> int:
        # Convert Unix time (seconds since 1970-01-01)
        # to Windows FILETIME (100-ns intervals since 1601-01-01)
        return (unix_time + 11644473600) * 10_000_000
    

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
    
    
    def get_directory_contents(self, remote_path: str):
        cmd = f'dirlist name="{remote_path}"\r\n'
        resp = self.send_command(cmd)
        if resp.code != 200:
            raise RuntimeError(f"Failed to list directory: {remote_path}")

        lines = resp.message.strip().splitlines()
        entries = []
        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                continue
            is_directory = parts[0] == "dir"
            name = " ".join(parts[2:])
            entries.append({"name": name, "is_directory": is_directory})
        return entries
    
    
    def get_kernel_version(self) -> str:
        cmd = f"consolefeatures ver=2 type=13 params=\"A\\0\\A\\0\\\""
        resp = self.send_command(cmd)
        return resp.message.strip()


    def get_modules(self) -> list:
        cmd = f"modules"
        lines = self.send_multiline_command(cmd)
        return lines
    
    
    def is_directory(self, path: str) -> bool:
        command = "dirlist name=\"" + path + "\""
        response = self.send_command(command)
        if response.code == 202:
            return True
        elif response.code == 410:
            return False
        else:
            raise RuntimeError(f"Unexpected response code: {response.code}")
        
    
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
        
        raise TypeError("Unsupported return type")
    

    def read_memory(self, address: int, size: int) -> bytes:
        resp = read_memory_text(self.conn, address, size)
        return resp
    

    def read_float(self, address: int) -> float:
        raw = read_memory_text(self.conn, address, 4)
        raw = raw[::-1]
        return struct.unpack('<f', raw)[0]
    

    def read_double(self, address: int) -> float:
        raw = read_memory_text(self.conn, address, 8)
        raw = raw[::-1]
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
    
    
    def read_wstring(self, address: int, max_length: int = 256) -> str:
        data = bytearray()
        for i in range(max_length):
            bytes_ = self.read_memory(address + i*2, 2)
            if bytes_ == b'\x00\x00':
                break
            data.extend(bytes_)
        return data.decode('utf-16le')
    
    
    def receive_directory(self, remote_path: str, local_path: str):
        import os
        files = self.get_directory_contents(remote_path)

        if not os.path.exists(local_path):
            os.makedirs(local_path)

        for file in files:
            next_directory = os.path.join(local_path, file['name'])

            if file['is_directory']:
                self.receive_directory(f"{remote_path}\\{file['name']}", next_directory)
            else:
                self.receive_file(f"{remote_path}\\{file['name']}", next_directory)

    def receive_file(self, remote_path: str, local_path: str):
        with open(local_path, 'wb') as file:
            cmd = f'getfile name="{remote_path}"\r\n'
            self.conn.send(cmd.encode())

            header = self.conn.recv_line() 
            if not header.startswith(b'203- binary response follows'):
                raise RuntimeError("Couldn't receive the file")

            file_size_bytes = self.conn.recv_exact(4)
            file_size = int.from_bytes(file_size_bytes, 'little')

            bytes_received = 0
            while bytes_received < file_size:
                chunk = self.conn.recv_exact(min(4096, file_size - bytes_received))
                if not chunk:
                    break
                file.write(chunk)
                bytes_received += len(chunk)

    
    def resolve_function(self, module_name: str, ordinal: int) -> int:
        hex_module = ''.join(f"{ord(c):02X}" for c in module_name)

        cmd = f'consolefeatures ver=2 type=9 params="A\\0\\A\\2\\{self.BYTE_ARRAY}/{len(hex_module)//2}\\{hex_module}\\{self.INT}\\{ordinal}\\"'
        resp = self.send_command(cmd)
        return int(resp.message.strip(), 16)
    

    def parse_hex_field(self, text: str, key: str) -> int:
        """
        Extract hex field like key=0x1234 from the metadata line.
        """
        m = re.search(rf"{key}=0x([0-9a-fA-F]+)", text)
        if not m:
            raise ValueError(f"Missing field: {key}")
        return int(m.group(1), 16)
    

    def _parse_hex_field_optional(self, text: str, key: str, default: int = 0) -> int:
        m = re.search(rf"{key}=0x([0-9a-fA-F]+)", text)
        if not m:
            return default
        return int(m.group(1), 16)

    def _xg_address_2d_tiled_offset(self, x: int, y: int, width: int, bytes_per_pixel: int) -> int:
        """
        Xbox 360 GPU 2D tiled surface address calculation.
        Based on Xenia emulator's texture_address::Tiled2D.

        The tiled address is composed of:
          - outer_blocks: macro tile (32x32) origin within the surface
          - inner_blocks: pixel offset within the macro tile using y[3:1], x[2:0]
          - bank/pipe: memory interleaving bits derived from x[4:3] and y[4:3]
          - y LSB: bit 0 of y goes to bit 4 of the address
        """
        aligned_width = (width + 31) & ~31
        log_bpp = {1: 0, 2: 1, 4: 2, 8: 3, 16: 4}[bytes_per_pixel]

        # Macro tile addressing (32x32 blocks, laid out linearly)
        macro_tiles_per_row = aligned_width >> 5
        outer_blocks = ((y >> 5) * macro_tiles_per_row + (x >> 5)) << 6

        # Inner block addressing within the macro tile
        # Uses y[3:1] and x[2:0] = 6 bits
        inner_blocks = (((y >> 1) & 0b111) << 3) | (x & 0b111)

        # Combine and scale to bytes
        outer_inner_bytes = (outer_blocks | inner_blocks) << log_bpp

        # Bank and pipe selection (memory interleaving with XOR)
        bank = (y >> 4) & 1
        pipe = ((x >> 3) & 0b11) ^ (((y >> 3) & 1) << 1)
        y_lsb = y & 1

        # Stitch all bits together per hardware layout:
        #   [3:0]  = outer_inner_bytes[3:0]
        #   [4]    = y LSB
        #   [5]    = outer_inner_bytes[4]
        #   [7:6]  = pipe
        #   [10:8] = outer_inner_bytes[7:5]
        #   [11]   = bank
        #   [31:12] = outer_inner_bytes[31:8]
        return (
            (outer_inner_bytes & 0xF) |
            (y_lsb << 4) |
            (((outer_inner_bytes >> 4) & 1) << 5) |
            (pipe << 6) |
            (((outer_inner_bytes >> 5) & 0b111) << 8) |
            (bank << 11) |
            ((outer_inner_bytes >> 8) << 12)
        )

    def _morton2d(self, x: int, y: int) -> int:
        def part1by1(n: int) -> int:
            n &= 0x0000FFFF
            n = (n | (n << 8)) & 0x00FF00FF
            n = (n | (n << 4)) & 0x0F0F0F0F
            n = (n | (n << 2)) & 0x33333333
            n = (n | (n << 1)) & 0x55555555
            return n

        return part1by1(x) | (part1by1(y) << 1)

    def _xg_address_2d_morton_offset(self, x: int, y: int, width: int, bytes_per_pixel: int) -> int:
        aligned_width = (width + 31) & ~31
        macro_tile_pitch = aligned_width >> 5

        macro_x = x >> 5
        macro_y = y >> 5
        macro_tile_index = macro_x + macro_y * macro_tile_pitch
        macro_tile_offset = macro_tile_index * (32 * 32 * bytes_per_pixel)

        local_x = x & 31
        local_y = y & 31
        morton = self._morton2d(local_x, local_y)

        return macro_tile_offset + morton * bytes_per_pixel

    def _infer_tiled_dimensions(self, width: int, height: int, fbsize: int, bytes_per_pixel: int):
        min_w = (width + 31) & ~31
        min_h = (height + 31) & ~31
        pixels = fbsize // bytes_per_pixel

        for w in range(min_w, min_w + 32 * 64, 32):
            if w <= 0:
                continue
            if pixels % w != 0:
                continue
            h = pixels // w
            if h >= min_h and h % 32 == 0:
                return w, h

        return min_w, min_h

    def untile_xenos_rgba(self, buffer, width, height, fbsize):
        """
        Untile Xbox 360 GPU surface using XG tiled addressing (Credits to Xenia Team).
        width should be the surface pitch in pixels (pitch_bytes / bytes_per_pixel).
        Vectorised with NumPy for performance.
        """
        bytes_per_pixel = 4
        log_bpp = 2  # log2(4)
        aligned_width = (width + 31) & ~31
        macro_tiles_per_row = aligned_width >> 5

        # Build coordinate grids (y rows, x cols)
        yy, xx = np.mgrid[0:height, 0:width].astype(np.int64)

        # --- Tiled address calculation (vectorised Tiled2D) ---
        outer_blocks = ((yy >> 5) * macro_tiles_per_row + (xx >> 5)) << 6
        inner_blocks = (((yy >> 1) & 0b111) << 3) | (xx & 0b111)
        outer_inner_bytes = (outer_blocks | inner_blocks) << log_bpp

        bank = (yy >> 4) & 1
        pipe = ((xx >> 3) & 0b11) ^ (((yy >> 3) & 1) << 1)
        y_lsb = yy & 1

        src = (
            (outer_inner_bytes & 0xF)
            | (y_lsb << 4)
            | (((outer_inner_bytes >> 4) & 1) << 5)
            | (pipe << 6)
            | (((outer_inner_bytes >> 5) & 0b111) << 8)
            | (bank << 11)
            | ((outer_inner_bytes >> 8) << 12)
        ).ravel()

        # --- Gather pixels via NumPy advanced indexing ---
        fb = np.frombuffer(buffer, dtype=np.uint8)
        max_src = len(fb) - bytes_per_pixel

        # Clamp out-of-bounds offsets to 0 (will be masked to black)
        valid = src <= max_src
        safe_src = np.where(valid, src, 0)

        # Gather 4 bytes per pixel using a view trick
        fb_u32 = np.frombuffer(buffer, dtype=np.uint32)
        src_u32 = (safe_src >> 2).astype(np.intp)  # byte offset -> u32 index
        out_u32 = np.where(valid, fb_u32[src_u32], 0).astype(np.uint32)

        return out_u32.view(np.uint8).tobytes()

    def untile_xenos_rgba_morton(self, buffer, width, height, fbsize):
        """
        Untile Xbox 360 GPU surface using Morton order within 32x32 tiles.
        """
        bytes_per_pixel = 4
        aligned_width, aligned_height = self._infer_tiled_dimensions(
            width,
            height,
            fbsize,
            bytes_per_pixel,
        )
        out = bytearray(width * height * bytes_per_pixel)

        expected_size = aligned_width * aligned_height * bytes_per_pixel
        max_size = min(len(buffer), expected_size)

        for y in range(height):
            for x in range(width):
                src = self._xg_address_2d_morton_offset(x, y, aligned_width, bytes_per_pixel)
                dst = (y * width + x) * bytes_per_pixel
                if src + bytes_per_pixel <= max_size:
                    out[dst:dst + bytes_per_pixel] = buffer[src:src + bytes_per_pixel]

        return out


    def screenshot_name(self) -> str:
        """
        :param self: XBDMClient instance
        :return: Returns a string filename for the screenshot based on the current timestamp
        :rtype: str
        """
        timestamp = time.strftime("%Y-%m-%d-%H-%M-%S-%MS", time.localtime())
        return f"{timestamp}.png"



    def screenshot(self, output_path: Optional[str] = None, rawmode: str = "BGRA", untile_mode: str = "xg") -> str:
        resp = self.send_command("screenshot")

        if resp.code != 203:
            raise RuntimeError("Screenshot failed")

        meta = self.conn.recv_line().decode("ascii", errors="ignore")
        pitch = self.parse_hex_field(meta, "pitch")
        width = self.parse_hex_field(meta, "width")
        height = self.parse_hex_field(meta, "height")
        fbsize = self.parse_hex_field(meta, "framebuffersize")
        sw = self._parse_hex_field_optional(meta, "sw", width)
        sh = self._parse_hex_field_optional(meta, "sh", height)
        off_x = self._parse_hex_field_optional(meta, "offsetx", 0)
        off_y = self._parse_hex_field_optional(meta, "offsety", 0)

        fb = self.conn.recv_exact(fbsize)
        if len(fb) != fbsize:
            raise RuntimeError("Framebuffer size mismatch")

        pitch_pixels = pitch // 4

        if untile_mode == "xg":
            linear = self.untile_xenos_rgba(fb, pitch_pixels, height, fbsize)
        elif untile_mode == "morton":
            linear = self.untile_xenos_rgba_morton(fb, pitch_pixels, height, fbsize)
        else:
            raise ValueError(f"Unknown untile_mode: {untile_mode}")

        # Build image from the untiled buffer using Pillow
        img = Image.frombuffer(
            "RGBA",
            (pitch_pixels, height),
            bytes(linear),
            "raw",
            rawmode,
            0,
            1,
        ).convert("RGB")

        # Crop to actual width if pitch is wider than the visible area
        if pitch_pixels > width:
            img = img.crop((0, 0, width, height))

        # Paste onto larger canvas if there is an offset
        if off_x != 0 or off_y != 0:
            canvas = Image.new("RGB", (sw, sh), (0, 0, 0))
            canvas.paste(img, (off_x, off_y))
            img = canvas

        # Nearest-neighbour resize when surface size differs from display size
        if (sw, sh) != (width, height):
            img = img.resize((sw, sh), Image.NEAREST)

        # Resolve output directory
        if output_path is None:
            pictures_dir = os.path.join(os.path.expanduser("~"), "Pictures")
            if os.path.isdir(pictures_dir):
                output_path = os.path.join(pictures_dir, "Solace 360 Screenshots")
            else:
                output_path = os.path.join(tempfile.gettempdir(), "Solace 360 Screenshots")

        os.makedirs(output_path, exist_ok=True)
        file_path = os.path.join(output_path, self.screenshot_name())
        # if android, save to shared pictures
        if os.name == "posix" and "ANDROID_ROOT" in os.environ:
            # retrieve androids shared pictures directory
            file_path = os.path.join(os.getenv('EXTERNAL_STORAGE'), "/storage/emulated/0", 'Pictures', 'Solace 360 Screenshots', self.screenshot_name())
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
        img.save(file_path, format="PNG")
        return file_path


    def send_command(self, command: str):
        self.conn.send(command.encode() + b"\r\n")
        line = self.conn.recv_line()
        return parse_response_line(line)
    
    
    def send_binary(self, data: bytes):
        self.conn.send(data)


    def send_multiline_command(self, command: str) -> list:
        lines = []
        response = self.send_command(command)

        if response.code == 202: # multiline response
            while True:
                line = self.conn.recv_line()
                decoded_line = line.decode().strip()
                if decoded_line == ".":
                    break
                lines.append(decoded_line)

        return lines


    def set_system_time(self, unix_time: int):
        filetime = self.timet_to_filetime(unix_time)

        clock_hi = (filetime >> 32) & 0xFFFFFFFF
        clock_lo = filetime & 0xFFFFFFFF

        command = (
            f"setsystime "
            f"clockhi=0x{clock_hi:08X} "
            f"clocklo=0x{clock_lo:08X}"
        )

        response = self.send_command(command)
        if response.code != 200:
            raise Exception(f"Failed to set system time with error code {response.code}\nMessage: {response.message}")
        
    def send_directory(self, local_path: str, remote_path: str):
        for entry in os.listdir(local_path):
            local_entry_path = os.path.join(local_path, entry)
            remote_entry_path = f"{remote_path}\\{entry}"

            if os.path.isdir(local_entry_path):
                self.create_directory(remote_entry_path)
                self.send_directory(local_entry_path, remote_entry_path)
            else:
                self.send_file(local_entry_path, remote_entry_path)
        

    def send_file(self, local_path: str, remote_path: str):
        with open(local_path, 'rb') as file:
            file.seek(0, 2)
            file_size = file.tell()
            file.seek(0, 0)

            cmd = f'sendfile name="{remote_path}" length=0x{file_size:X}\r\n'
            self.conn.send(cmd.encode())

            header = self.conn.recv_line()
            if not header.startswith(b'204- send binary data'):
                raise RuntimeError("Couldn't send the file")

            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                self.conn.send(chunk)

            final_response = self.conn.recv_line()
            if not final_response.startswith(b'200- OK'):
                raise RuntimeError("File transfer failed")
            
    def shutdown_console(self):
        command = "consolefeatures ver=2 type=11 params=\"A\\0\\A\\0\\\""
        response = self.send_command(command)
        if response.code != 200:
            raise Exception(f"Failed to shutdown console with error code {response.code}\nMessage: {response.message}")
        
            
    def synchronize_time(self):
        now = int(time.time())
        self.set_system_time(now)
            
    def unload_module(self, module: str):
        address = self.resolve_function("xam.xex", 1102)
        handle = self.call_int(address, [module])
        if handle != 0:
            self.write_u16(handle + 0x40, 1)
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

    def write_float_vector2(self, address: int, x: float, y: float):
        data = struct.pack('<ff', x, y)
        data = data[::-1]
        write_memory(self.conn, address, data)
    
    def write_float_vector3(self, address: int, x: float, y: float, z: float):
        data = struct.pack('<fff', x, y, z)
        data = data[::-1]
        write_memory(self.conn, address, data)

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

    def write_u16(self, address: int, value: int):
        write_memory(self.conn, address, value.to_bytes(2, 'big'))

    def write_u32(self, address: int, value: int) -> None:
        write_memory(self.conn, address, value.to_bytes(4, 'big'))

    def write_u64(self, address: int, value: int) -> None:
        write_memory(self.conn, address, value.to_bytes(8, 'big'))

    def write_u16_array(self, address: int, values: list):
        data = bytearray()
        for value in values:
            data.extend(value.to_bytes(2, 'big'))
        write_memory(self.conn, address, data)

    def write_u32_array(self, address: int, values: list):
        data = bytearray()
        for value in values:
            data.extend(value.to_bytes(4, 'big'))
        write_memory(self.conn, address, data)

    def write_u64_array(self, address: int, values: list):
        data = bytearray()
        for value in values:
            data.extend(value.to_bytes(8, 'big'))
        write_memory(self.conn, address, data)

    def write_wstring(self, address: int, string: str):
        data = string.encode('utf-16le')
        write_memory(self.conn, address, data)

    def xnotify(self, text: str, type: int = 34) -> None:
        cmd = f'consolefeatures ver=2 type=12 params="A\\0\\A\\2\\{self.BYTE_ARRAY}/{len(text)}\\{text.encode("ascii").hex().upper()}\\{self.INT}\\{type}\\"'
        self.send_command(cmd)

    def zero_memory(self, address: int, size: int):
        zero_data = bytes(size)
        write_memory(self.conn, address, zero_data)

