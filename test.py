def gen_jmp(dst, cur):
    dstb = (dst - cur + 0xFFFFFFFF - 4) & 0xFFFFFFFF
    a = (dstb >> 24) & 0xff
    b = (dstb >> 16) & 0xff
    c = (dstb >> 8) & 0xff
    d = dstb & 0xFF
    final_bytes = [0xe9, d, c, b, a]
    return final_bytes

a = gen_jmp(0x1,0x3)
print(a)