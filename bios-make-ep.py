# bios-make-ep script for IDA
# (c) AVET Information and Network Security Sp. z o.o. 2010
# For more info visit us at: http://www.avet.com.pl
# Not for commercial use

from idaapi import *

def make_reloc(src, dst, hi_add):
    bOk = False
    limit = src + hi_add
    ea_dest = dst
    ea_src = src

    while ea_src <= limit:
        dd = Dword(ea_src)
        if dd != -1:
            PatchDword(ea_dest, dd)
            ea_src += 4
            ea_dest += 4
        else:
            print 'ERROR: value at %X can not be treated as dword.' % ea_src
            return False

    return True


bOk = None
bios_segname = '_F000'
bios_segstart = (0xf000 << 4) + 0
bios_segend = (0x10000 << 4) + 0
bios_base = 0xf000
bios_entrypoint = (0xf000 << 4) + 0xfff0
reloc_base = (0x7000 << 4) + 0
hi_limit = 0x10000

print 'Parsing file %s.' % get_input_file_path()
print 'Creating segment for BIOS code:',

bOk = AddSeg(bios_segstart, bios_segend, bios_base, 0, 0, 0)
if bOk:
    print 'Done. Now rename new segment to %s:' % bios_segname,
    bOk = SegRename(bios_segstart, bios_segname)
    if bOk:
        print 'Done. Now populate segment %s with code' % bios_segname,
        bOk = make_reloc(reloc_base, bios_segstart, hi_limit)
        if bOk:
            print 'Done.'

            if Byte(bios_entrypoint) == 0xEA:
                print 'BIOS Entry point found at %X.' % bios_entrypoint
                AddEntryPoint(bios_entrypoint, bios_entrypoint, 'BIOS_Entry', 1)

    else:
        print 'ERROR: SegRename failed.'
else:
    print 'ERROR: AddSeg failed.'
