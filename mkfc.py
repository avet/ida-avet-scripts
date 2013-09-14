# mkfc script for IDA
# (c) AVET Information and Network Security Sp. z o.o. 2010 - 2013
# For more info visit us at: http://www.avet.com.pl
# Not for commercial use

from idc import *
from idaapi import *

function_list = {}
entry_byte = []
new_funcs = []

ea = ScreenEA()
addr = SegStart(ea)

while addr < SegEnd(ea) and addr != BADADDR:
    if isUnknown(GetFlags(addr)):
        print 'Unknow loc: %08X' % addr
        addr = NextHead(addr, BADADDR)
    else:
        addr = NextAddr(addr)

for _func in Functions(SegStart(ea), SegEnd(ea)):
    b = Byte(_func)
    if not b in entry_byte:
        entry_byte.append(b)
    f_end = FindFuncEnd(_func)
    function_list[_func] = f_end
    print 'Identified function at: %08X - %08X' % (_func, f_end)

print 'IDA found %d functions' % len(function_list)

for i in function_list.keys():
    end_addr = function_list[i]

    if end_addr not in function_list.keys():
        MakeCode(end_addr)
        MakeFunction(end_addr,BADADDR)
        print 'Found new function at: %08X = %02X' % (end_addr, Byte(end_addr)),
        if Byte(end_addr) in entry_byte:
            print ' possible function prolog found!'
        else:
            print ''

        new_funcs.append(end_addr)

print 'Found %d new functions' % len(new_funcs)
