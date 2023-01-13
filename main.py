from unicorn import *
import capstone
from unicorn.x86_const import *
import argparse
import sys

cp1 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
start_addr = []
end_addr = []
start_dest = {}
tmp_dest = None
dest_dict = {}


def gen_jmp(dst, cur):
    if cur == -1:
        cur = 0
    dst = int(dst, 16)
    dstb = (dst - cur + 0xFFFFFFFF - 4) & 0xFFFFFFFF
    a = (dstb >> 24) & 0xff
    b = (dstb >> 16) & 0xff
    c = (dstb >> 8) & 0xff
    d = dstb & 0xFF
    final_bytes = [0xe9, d, c, b, a]
    fb = bytes(final_bytes)
    for i in cp1.disasm(fb, 0, len(fb)):
        print(i.mnemonic + " " + i.op_str)
    return final_bytes


def hook_code(uc, address, size, user_data):
    global tmp_dest
    for i in cp1.disasm(uc.mem_read(address, size), 0, size):
        if i.mnemonic == "call":
            uc.reg_write(UC_X86_REG_EIP, address + size)
        elif address in start_addr and address != 1:
            tmp_dest = address
            print("DESTINATION FOUND")
            uc.emu_stop()


def main():
    parser = argparse.ArgumentParser(description="deflat alcatarz control flow")
    parser.add_argument("-f", "--file", help="binary to analyze")
    parser.add_argument(
        "--addr", help="file offset of target function in hex format")
    parser.add_argument("-s", "--size", help="target function size")
    args = parser.parse_args()

    if args.file is None or args.addr is None or args.size is None:
        parser.print_help()
        sys.exit(0)

    filename = args.file
    start = int(args.addr, 16)
    size = int(args.size , 16)
    f = open(filename, 'rb')
    code = f.read()[start:start + size]
    print(str(bytes(code)))
    cp = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    f.close()
    ADDRESS = 0x0
    global tmp_dest
    flag1 = False
    for i in cp.disasm(code, 0, len(code)):
        if i.mnemonic == "popf":  # find the start of a function block
            start_addr.append(ADDRESS + i.address)
            flag1 = True

        elif i.mnemonic == "pushf":
            end_addr.append(ADDRESS + i.address - 1)  # start from push rax, 1 byte before pushf
        elif flag1 and i.mnemonic == "jmp":
            print(f"popf at {hex(i.address - 3)} to {i.op_str}")
            start_dest[ADDRESS + i.address - 3] = i.op_str
            flag1 = False
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(ADDRESS, 10 * 1024 * 1024)
        mu.mem_write(ADDRESS, code)
        mu.reg_write(UC_X86_REG_RSP, ADDRESS + 0x20000)
        for addr in end_addr:
            mu.hook_add(UC_HOOK_CODE, hook_code, None, addr, len(code) - addr)
            mu.emu_start(addr, ADDRESS + len(code))
            if tmp_dest is not None:  # found the true successor
                dest_dict[addr] = tmp_dest
                tmp_dest = None
            else:
                raise RuntimeError("Couldn't find the successor")
    except UcError as e:
        print("ERROR: %s" % e)
    print(">>> Emulation done. Start Patching")
    with open("obf.exe", 'rb') as f:
        orgdata = f.read()
    orgarr = bytearray(orgdata)
    for end in dest_dict:
        dst = start_dest[dest_dict[end]]
        jmp = gen_jmp(dst, end)
        jmp.extend([0x90] * 8)
        for i in range(0, 13):
            orgarr[start + end + i] = jmp[i]

    with open(filename+"_deobf.exe", 'wb') as f:
        f.write(bytes(orgarr))
        print("writing patch to:" + filename+"_deobf.exe")


if __name__ == "__main__":
    main()
