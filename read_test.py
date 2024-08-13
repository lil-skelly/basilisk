import struct
import io 
import itertools
import zlib
import random

class CmdBuffer:
    def __init__(self, cmd: int, pid: int) -> None:
        self.cmd = cmd
        self.pid = pid
        self.buffer = io.BytesIO()
        self.__rand_bytes = random.getrandbits(32).to_bytes(4, "little") # 4-bytes of random data

    def __str__(self):
        return f"<CmdBuffer>: cmd: {self.cmd} | pid: {self.pid} | rand bytes: {self.__rand_bytes}"

    def set_cmd(self, cmd: int):
        if not isinstance(cmd, int):
            raise ValueError(f"cmd must be of type `int` ({type(cmd)} given)")

        if cmd > 0xffffffff:
            raise ValueError("Value exceeds range 0x00000000..0xffffffff")
        self.cmd = cmd

    def set_pid(self, pid: int):
        if not isinstance(pid, int):
            raise ValueError(f"cmd must be of type `int` ({type(pid)} given)")
        self.pid = pid

    def __append_rand_bytes(self, n: int):
        self.buffer.write(self.__rand_bytes)
    
    def __append_pid(self):
        self.buffer.write(struct.pack("<I", self.pid))
    
    def __append_crc(self):
        self.buffer.seek(0)
        data = self.buffer.getvalue()
        
        crc = struct.pack("<I", zlib.crc32(data))
        self.buffer.write(crc)

    def finalize(self):
        self.buffer.write(struct.pack("<B", self.cmd))
        self.__append_rand_bytes(4)
        self.__append_pid()
        self.__append_crc()
        self.buffer.seek(0)
        print("".join(f"{byte:02X}" for byte in self.buffer.read()))
my_cmd = CmdBuffer(0xba, 6)
print(my_cmd.pid, my_cmd.cmd)
print(my_cmd)
my_cmd.finalize()


#buf = bytearray(1024)
#fd = io.open("/proc/kallsyms", "rb", 0)
#for i in itertools.count():
#    num_read = fd.readinto(buf)
#    if not num_read:
#        break;
