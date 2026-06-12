#!/usr/bin/env python3
"""Regenerate sboxes.h (the two key-independent Khafre S-boxes) for solve.c."""
import sphinx_model as S
with open("sboxes.h", "w") as f:
    f.write("#include <stdint.h>\n")
    for i in (0, 1):
        f.write("static const uint32_t SB%d[256] = {" % i)
        f.write(",".join("0x%08xu" % S.SBOXES[i][j] for j in range(256)))
        f.write("};\n")
print("wrote sboxes.h")
