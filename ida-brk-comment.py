# ida-brk-comment script for IDA
# (c) AVET Information and Network Security Sp. z o.o. 2012
# For more info visit us at: http://www.avet.com.pl
# Not for commercial use

from idaapi import *
chooser = Choose([],'Breakpoint comments',1)
comments = {}
breakpoints = {}
brk_no = GetBptQty()

print 'Breakpoints = %d' % brk_no

for i in range(0,brk_no):
    brk_addr = GetBptEA(i)
    print '%d: %X' % (i+1, brk_addr)
    breakpoints[i] = brk_addr
    str = '%08X' % (brk_addr)
    if comments.has_key(i):
        str += ' %s' % comments[i]
    else:
        _c = CommentEx(breakpoints[i],0)
        if _c:
            str += '   ;%s' % (_c)
        else:
            str += '   ;no comment'

    print str
    chooser.list.append(str)


chooser.width = 50
ch = chooser.choose()

if ch > 0:
    _comment = AskStr('; ', 'Comment:')
    comments[ch] = _comment
    MakeComm(breakpoints[ch-1], _comment)
