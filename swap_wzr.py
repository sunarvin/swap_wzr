#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Author: Arvin Sun
# E-mail: sunarvin@hotmail.com
# You use at your own risk. The author is not responsible for any loss or damage the program involved.
#
# MIT license, all text above must be included in any redistribution.

import sys
from capstone import *
import struct


def get_text_section(filename: str):
    magic_s = ''

    with open(filename, 'rb') as f:
        buf = f.read(4)
        magic_s += ('%02x' % buf[3])
        magic_s += ('%02x' % buf[2])
        magic_s += ('%02x' % buf[1])
        magic_s += ('%02x' % buf[0])
        print(magic_s)

        if magic_s == 'feedfacf':
            print('64 LE')
#       elif magic_s == 'cffaedfe':
#           print('64 BE')
#       elif magic_s == 'feedface':
#           print('32 LE')
#       elif magic_s == 'cefaedfe':
#           print('32 BE')
        else:
            print('Unsupported type')

        # read header
        buf = f.read(28)
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, rsv0 = struct.unpack('7I', buf)
        print('command number: %d' % ncmds)

        found = False
        # search for __TEXT segment
        for i in range(ncmds):
            buf = f.read(8)
            cmd, cmdsize = struct.unpack('II', buf)
            print('cmd 0x%X size %d' % (cmd, cmdsize))

            if cmd == 25:  # segment type 25 (0x19 LC_SEGMENT_64)
                buf = f.read(16)
                seg_name = buf.decode('utf-8').rstrip('\0')
                print('segment name:', seg_name)

                if seg_name == '__TEXT':  # hit the __TEXT segment
                    buf = f.read(48)
                    vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack('4Q4I', buf)

                    # search for __text section
                    for j in range(nsects):
                        buf = f.read(16)
                        sec_name = buf.decode('utf-8').rstrip('\0')
                        print('section name:', sec_name)
                        buf = f.read(16)  # jump off segment name
                        buf = f.read(48)
                        if sec_name == '__text':  # hit the __text section
                            addr, size, offset, align, reloff, nreloc, flags, rsv1, rsv2, rsv3 = struct.unpack('2Q8I', buf)

                            f.seek(offset, 0)
                            code = f.read(size)

                            return code, addr, offset

            # move to the next segment
            f.seek(cmdsize-24, 1)


def search_modify_offset(code_bytes: bytes, text_addr: int):
    aarch64_cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    # search for (STP, WZR) instructions
    candidate = []
    for i in aarch64_cs.disasm(code_bytes, text_addr):
        if i.mnemonic == 'str' and i.op_str[0:4] == 'wzr,':
            # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            candidate.append(i)

    # search for two adjoining (STP, WZR) instruction
    prev = None
    for i in candidate:
        if (prev is not None) and (i.address-prev.address == 4):
            break
        else:
            prev = i

    # two adjoining instructions are found
    if prev is not None and i is not None:
        print("0x%x:\t%s\t%s" % (prev.address, prev.mnemonic, prev.op_str))
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

        # compute the offset in bytes
        offset = (prev.address - text_addr)
        return offset
    else:
        return None


def do_modify(filename: str, offset: int):
    with open(filename, 'rb+') as f:
        # read 8 bytes
        f.seek(offset)
        eight_bytes = f.read(8)
#       for byte in eight_bytes:
#           print(hex(byte))
        # swap and write back to file
        f.seek(offset)
        f.write(eight_bytes[4:8])
        f.write(eight_bytes[0:4])


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python %s <FILENAME>' % sys.argv[0])
        sys.exit()

    filename = sys.argv[1]
    code, text_addr, file_offset = get_text_section(filename)
    print('__text EA: 0x%X' % text_addr)
    print('__text offset in this file: 0x%X' % file_offset)

    offset = search_modify_offset(code, text_addr)
    if offset is None:
        print('Unable find two adjoining WZR instructions, exit')
        sys.exit()

    modify_offset = file_offset + offset
    print('Patch address in EA: 0x%X' % (modify_offset))
    print('Patch at file offset: 0x%X' % (modify_offset))
    do_modify(filename, modify_offset)
