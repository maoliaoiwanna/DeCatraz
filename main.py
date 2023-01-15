from unicorn import *
import capstone
import keystone
from unicorn.x86_const import *
import argparse
import sys

cp1 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
reg_dict = {"invalid": 0, "ah": 1, "al": 2, "ax": 3, "bh": 4, "bl": 5, "bp": 6, "bpl": 7, "bx": 8, "ch": 9, "cl": 10,
            "cs": 11, "cx": 12, "dh": 13, "di": 14, "dil": 15, "dl": 16, "ds": 17, "dx": 18, "eax": 19, "ebp": 20,
            "ebx": 21, "ecx": 22, "edi": 23, "edx": 24, "eflags": 25, "eip": 26, "es": 28, "esi": 29, "esp": 30,
            "fpsw": 31, "fs": 32, "gs": 33, "ip": 34, "rax": 35, "rbp": 36, "rbx": 37, "rcx": 38, "rdi": 39, "rdx": 40,
            "rip": 41, "rsi": 43, "rsp": 44, "si": 45, "sil": 46, "sp": 47, "spl": 48, "ss": 49, "cr0": 50, "cr1": 51,
            "cr2": 52, "cr3": 53, "cr4": 54, "cr8": 58, "dr0": 66, "dr1": 67, "dr2": 68, "dr3": 69, "dr4": 70,
            "dr5": 71, "dr6": 72, "dr7": 73, "fp0": 82, "fp1": 83, "fp2": 84, "fp3": 85, "fp4": 86, "fp5": 87,
            "fp6": 88, "fp7": 89, "k0": 90, "k1": 91, "k2": 92, "k3": 93, "k4": 94, "k5": 95, "k6": 96, "k7": 97,
            "mm0": 98, "mm1": 99, "mm2": 100, "mm3": 101, "mm4": 102, "mm5": 103, "mm6": 104, "mm7": 105, "r8": 106,
            "r9": 107, "r10": 108, "r11": 109, "r12": 110, "r13": 111, "r14": 112, "r15": 113, "st0": 114, "st1": 115,
            "st2": 116, "st3": 117, "st4": 118, "st5": 119, "st6": 120, "st7": 121, "xmm0": 122, "xmm1": 123,
            "xmm2": 124, "xmm3": 125, "xmm4": 126, "xmm5": 127, "xmm6": 128, "xmm7": 129, "xmm8": 130, "xmm9": 131,
            "xmm10": 132, "xmm11": 133, "xmm12": 134, "xmm13": 135, "xmm14": 136, "xmm15": 137, "xmm16": 138,
            "xmm17": 139, "xmm18": 140, "xmm19": 141, "xmm20": 142, "xmm21": 143, "xmm22": 144, "xmm23": 145,
            "xmm24": 146, "xmm25": 147, "xmm26": 148, "xmm27": 149, "xmm28": 150, "xmm29": 151, "xmm30": 152,
            "xmm31": 153, "ymm0": 154, "ymm1": 155, "ymm2": 156, "ymm3": 157, "ymm4": 158, "ymm5": 159, "ymm6": 160,
            "ymm7": 161, "ymm8": 162, "ymm9": 163, "ymm10": 164, "ymm11": 165, "ymm12": 166, "ymm13": 167, "ymm14": 168,
            "ymm15": 169, "ymm16": 170, "ymm17": 171, "ymm18": 172, "ymm19": 173, "ymm20": 174, "ymm21": 175,
            "ymm22": 176, "ymm23": 177, "ymm24": 178, "ymm25": 179, "ymm26": 180, "ymm27": 181, "ymm28": 182,
            "ymm29": 183, "ymm30": 184, "ymm31": 185, "zmm0": 186, "zmm1": 187, "zmm2": 188, "zmm3": 189, "zmm4": 190,
            "zmm5": 191, "zmm6": 192, "zmm7": 193, "zmm8": 194, "zmm9": 195, "zmm10": 196, "zmm11": 197, "zmm12": 198,
            "zmm13": 199, "zmm14": 200, "zmm15": 201, "zmm16": 202, "zmm17": 203, "zmm18": 204, "zmm19": 205,
            "zmm20": 206, "zmm21": 207, "zmm22": 208, "zmm23": 209, "zmm24": 210, "zmm25": 211, "zmm26": 212,
            "zmm27": 213, "zmm28": 214, "zmm29": 215, "zmm30": 216, "zmm31": 217, "r8b": 218, "r9b": 219, "r10b": 220,
            "r11b": 221, "r12b": 222, "r13b": 223, "r14b": 224, "r15b": 225, "r8d": 226, "r9d": 227, "r10d": 228,
            "r11d": 229, "r12d": 230, "r13d": 231, "r14d": 232, "r15d": 233, "r8w": 234, "r9w": 235, "r10w": 236,
            "r11w": 237, "r12w": 238, "r13w": 239, "r14w": 240, "r15w": 241, "idtr": 242, "gdtr": 243, "ldtr": 244,
            "tr": 245, "fpcw": 246, "fptag": 247, "msr": 248, "mxcsr": 249, "fs_base": 250, "gs_base": 251,
            "flags": 252, "rflags": 253, "fip": 254, "fcs": 255, "fdp": 256, "fds": 257, "fop": 258, "ending": 259}
start_addr = []
end_addr = []
start_dest = {}
tmp_dest = None
dest_dict = {}
mov_start = {}
mov_end = {}
mov_result = {}
tmp_emu_start = None


# generate the bytes of the jmp instruction
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
        print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
        if i.mnemonic == "call":
            uc.reg_write(UC_X86_REG_EIP, address + size)
        elif address in start_addr and address != 1:
            tmp_dest = address
            print("DESTINATION FOUND")
            uc.emu_stop()


def hook_code_mov(uc, address, size, user_data):
    print("demov: ins at 0x%x, instruction size = 0x%x , end at 0x%x" % (address, size, mov_end[tmp_emu_start]))
    if address == mov_end[tmp_emu_start]:
        op1 = None
        reg_num = None
        if mov_start.get(tmp_emu_start) is not None:
            op1 = mov_start.get(tmp_emu_start)
            reg_num = reg_dict.get(op1)
        print("mov result :" + str(hex(uc.reg_read(reg_num))))
        if mov_result.get(tmp_emu_start) is not None:
            mov_result[tmp_emu_start].extend([uc.reg_read(reg_num), op1])
        else:
            mov_result[tmp_emu_start] = [uc.reg_read(reg_num), op1]
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
    size = int(args.size, 16)
    f = open(filename, 'rb')
    code = f.read()[start:start + size]
    cp = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    f.close()
    ADDRESS = 0x0
    global tmp_dest
    global tmp_emu_start
    flag1 = False
    prev = ""
    pre_prev = ""
    op = ""
    for i in cp.disasm(code, 0, len(code)):
        print("[0x%x]:%s %s" % (i.address, i.mnemonic, i.op_str))
        if i.mnemonic + " " + i.op_str == "pop rax" and prev == "popf ":  # find the start of a function block
            start_addr.append(ADDRESS + i.address - 2)  # start from popf, 2 byte before pop rax
            pre_prev = prev
            prev = i.mnemonic + " " + i.op_str
            flag1 = True

        elif i.mnemonic + " " + i.op_str == "pushf " and prev == "push rax":
            pre_prev = prev
            prev = i.mnemonic + " " + i.op_str
            end_addr.append(ADDRESS + i.address - 1)  # start from push rax, 1 byte before pushf
        elif flag1 and i.mnemonic == "jmp":
            start_dest[ADDRESS + i.address - 3] = i.op_str
            pre_prev = prev
            prev = i.mnemonic + " " + i.op_str
            flag1 = False
        elif i.mnemonic + " " + i.op_str == "pushf " and (
                prev[0:4] == "mov " or prev[0:6] == "movabs"):  # found a mov obfuscated block
            if prev[0:4] == "mov ":  # start emulation from the initial mov of the register
                op = prev.split(",")[0][4:]
                mov_start[i.address - 5] = op
            elif prev[0:6] == "movabs":
                op = prev.split(",")[0][7:]
                mov_start[i.address - 10] = op
                mov_result[i.address - 10] = ["abs"]
            pre_prev = prev
            prev = i.mnemonic + " " + i.op_str
        elif i.mnemonic != "pushf" and prev[0:4] == "popf" and pre_prev[0:3] == "rol":  # the end of a mov obfuscation
            assert pre_prev[4:7] == op

            mov_end[list(mov_start.keys())[-1]] = i.address - 2
            pre_prev = prev
            prev = i.mnemonic + " " + i.op_str
        else:
            pre_prev = prev
            prev = i.mnemonic + " " + i.op_str
    # deobfuscate the control flow flattening
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

    # deobfuscate the mov
    try:
        mu1 = Uc(UC_ARCH_X86, UC_MODE_64)
        mu1.mem_map(ADDRESS, 10 * 1024 * 1024)
        mu1.mem_write(ADDRESS, code)
        mu1.reg_write(UC_X86_REG_RSP, ADDRESS + 0x20000)
        for addr in mov_start:
            tmp_emu_start = addr
            mu1.hook_add(UC_HOOK_CODE, hook_code_mov, None, addr, len(code) - addr)
            mu1.emu_start(addr, ADDRESS + len(code))
    except UcError as e:
        print("ERROR: %s" % e)

    print(">>> Emulation done. Start Patching")
    with open(filename, 'rb') as f:
        orgdata = f.read()
    orgarr = bytearray(orgdata)

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    for movstart in mov_result:  # patching the jmp is prior to mov because it has longer length
        end = mov_end[movstart]
        r = mov_result.get(movstart)
        if len(r) == 3:
            insn = f"movabs {r[2]}, {hex(r[1])}"
        else:
            insn = f"mov {r[1]}, {hex(r[0])}"
        encoding, count = ks.asm(insn.encode("utf-8"))
        encoding.extend([0x90] * (end + 1 - movstart - len(encoding)))
        for i in range(movstart, end + 2):
            if i - movstart < len(encoding):
                orgarr[start + i] = encoding[i - movstart]
            else:
                orgarr[start + i] = 0x90
            print(f"patching {hex(i)}")

    for end in dest_dict:
        dst = start_dest[dest_dict[end]]
        jmp = gen_jmp(dst, end)
        jmp.extend([0x90] * 8)
        for i in range(0, 13):
            orgarr[start + end + i] = jmp[i]

    with open(filename + "_deobf.exe", 'wb') as f:
        f.write(bytes(orgarr))
        print("writing patch to:" + filename + "_deobf.exe")


if __name__ == "__main__":
    main()
