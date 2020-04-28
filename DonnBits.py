'''
    This script implements the DonnBits decompression algorithm
    found in the 'dcmp' 0 resource.
'''

import struct

const_words_tab = (
    0x0000, 0x4EBA, 0x0008, 0x4E75, 0x000C, 0x4EAD, 0x2053, 0x2F0B,
    0x6100, 0x0010, 0x7000, 0x2F00, 0x486E, 0x2050, 0x206E, 0x2F2E,
    0xFFFC, 0x48E7, 0x3F3C, 0x0004, 0xFFF8, 0x2F0C, 0x2006, 0x4EED,
    0x4E56, 0x2068, 0x4E5E, 0x0001, 0x588F, 0x4FEF, 0x0002, 0x0018,
    0x6000, 0xFFFF, 0x508F, 0x4E90, 0x0006, 0x266E, 0x0014, 0xFFF4,
    0x4CEE, 0x000A, 0x000E, 0x41EE, 0x4CDF, 0x48C0, 0xFFF0, 0x2D40,
    0x0012, 0x302E, 0x7001, 0x2F28, 0x2054, 0x6700, 0x0020, 0x001C,
    0x205F, 0x1800, 0x266F, 0x4878, 0x0016, 0x41FA, 0x303C, 0x2840,
    0x7200, 0x286E, 0x200C, 0x6600, 0x206B, 0x2F07, 0x558F, 0x0028,
    0xFFFE, 0xFFEC, 0x22D8, 0x200B, 0x000F, 0x598F, 0x2F3C, 0xFF00,
    0x0118, 0x81E1, 0x4A00, 0x4EB0, 0xFFE8, 0x48C7, 0x0003, 0x0022,
    0x0007, 0x001A, 0x6706, 0x6708, 0x4EF9, 0x0024, 0x2078, 0x0800,
    0x6604, 0x002A, 0x4ED0, 0x3028, 0x265F, 0x6704, 0x0030, 0x43EE,
    0x3F00, 0x201F, 0x001E, 0xFFF6, 0x202E, 0x42A7, 0x2007, 0xFFFA,
    0x6002, 0x3D40, 0x0C40, 0x6606, 0x0026, 0x2D48, 0x2F01, 0x70FF,
    0x6004, 0x1880, 0x4A40, 0x0040, 0x002C, 0x2F08, 0x0011, 0xFFE4,
    0x2140, 0x2640, 0xFFF2, 0x426E, 0x4EB9, 0x3D7C, 0x0038, 0x000D,
    0x6006, 0x422E, 0x203C, 0x670C, 0x2D68, 0x6608, 0x4A2E, 0x4AAE,
    0x002E, 0x4840, 0x225F, 0x2200, 0x670A, 0x3007, 0x4267, 0x0032,
    0x2028, 0x0009, 0x487A, 0x0200, 0x2F2B, 0x0005, 0x226E, 0x6602,
    0xE580, 0x670E, 0x660A, 0x0050, 0x3E00, 0x660C, 0x2E00, 0xFFEE,
    0x206D, 0x2040, 0xFFE0, 0x5340, 0x6008, 0x0480, 0x0068, 0x0B7C,
    0x4400, 0x41E8, 0x4841, 0x0000
)

def SignExtend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


def PutWord(dst, val):
    dst.append((val >> 8) & 0xFF)
    dst.append(val & 0xFF)


def GetVarLenInt(src, pos):
    val = src[pos]
    if val < 128:
        return val, 1
    elif val == 255:
        val = (src[pos+1] << 24) | (src[pos+2] << 16) | (src[pos+3] << 8) | src[pos+4]
        return val, 5
    else:
        val = (SignExtend(val * 512 - 0x8000, 16) >> 1) + src[pos+1]
        val = SignExtend(val, 16)
        return val, 2


def DonnDecompress(src, dst, unpackSize, pos=0):
    varTabRatio, overRun, algID, tabID = struct.unpack_from(">BBHH", src, pos)

    if tabID:
        print("Unsupported cTableID value: 0x%X" % tab_id)
        return

    if algID:
        print("Donn algorithm %d not supported yet" % alg_id)
        return

    pos += 6

    var_tab = []

    dstPos = 0

    while dstPos < unpackSize:
        tok = src[pos]
        pos += 1
        #print("Got token 0x%X" % tok)

        if tok <= 15:
            if tok == 0:
                length,size = GetVarLenInt(src, pos)
                pos += size
                length *= 2
            else:
                length = tok * 2

            for i in range(0, length):
                dst.append(src[pos])
                pos += 1
                dstPos += 1
        elif tok == 0x10:
            length,size = GetVarLenInt(src, pos)
            length *= 2
            pos += size
            var_tab.append((src[pos:pos+length], length))

            # then copy data over
            for i in range(0, length):
                dst.append(src[pos])
                pos += 1
                dstPos += 1
        elif tok >= 0x11 and tok <= 0x1F:
            length = (tok - 0x10) * 2
            # store stream bytes together with their length in the table
            var_tab.append((src[pos:pos+length], length))

            # then copy data over
            for i in range(0, length):
                dst.append(src[pos])
                pos += 1
                dstPos += 1
        elif tok == 0x20:
            data, length = var_tab[src[pos] + 40]
            pos += 1
            dst.extend(data)
            dstPos += length
        elif tok == 0x21:
            data, length = var_tab[src[pos] + 256 + 40]
            pos += 1
            dst.extend(data)
            dstPos += length
        elif tok >= 0x23 and tok <= 0x4A:
            data, length = var_tab[tok - 0x23]
            dst.extend(data)
            dstPos += length
        elif tok >= 0x4B and tok <= 0xFD:
            const_word = const_words_tab[tok - 0x4B]
            PutWord(dst, const_word)
            dstPos += 2
        elif tok == 0xFE:
            ext_op = src[pos]
            pos += 1
            if ext_op == 0:
                seg_num, size = GetVarLenInt(src, pos)
                pos += size
                num_entries, size = GetVarLenInt(src, pos)
                pos += size
                offset = 6
                for i in range(0, num_entries):
                    PutWord(dst, 0x3F3C)
                    PutWord(dst, seg_num)
                    PutWord(dst, 0xA9F0)
                    delta, size = GetVarLenInt(src, pos)
                    pos += size
                    offset = SignExtend(offset + delta - 6, 16)
                    PutWord(dst, offset)
                    dstPos += 8
                PutWord(dst, 0x3F3C)
                PutWord(dst, seg_num)
                PutWord(dst, 0xA9F0)
                dstPos += 6
            elif ext_op == 3:
                val, size = GetVarLenInt(src, pos)
                pos += size
                rep_count, size = GetVarLenInt(src, pos)
                pos += size
                if rep_count == 0:
                    print("Invalid RLE rep count = 0!")
                    return
                for i in range(0, rep_count + 1):
                    PutWord(dst, val)
                    dstPos += 2
            elif ext_op == 4:
                val, size = GetVarLenInt(src, pos)
                pos += size
                rep_count, size = GetVarLenInt(src, pos)
                pos += size
                PutWord(dst, val)
                dstPos += 2
                for i in range(0, rep_count):
                    val = val + SignExtend(src[pos+i], 8)
                    PutWord(dst, val)
                    dstPos += 2
                pos += rep_count
            else:
                print("Unsupported extension algorithm %d" % ext_op)
                return
        elif tok == 0xFF:
            # terminate decompression
            return
        else:
            print("Unsupported token 0x%X encountered" % tok)
            return
