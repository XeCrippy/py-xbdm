import struct

def u8(data):   return data[0]
def u16(data):  return struct.unpack(">H", data)[0]
def u32(data):  return struct.unpack(">I", data)[0]
def u64(data):  return struct.unpack(">Q", data)[0]

def s16(data):  return struct.unpack(">h", data)[0]
def s32(data):  return struct.unpack(">i", data)[0]
def s64(data):  return struct.unpack(">q", data)[0]
