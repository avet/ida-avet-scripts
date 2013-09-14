ida-avet-scripts
================

Collection of various scripts for IDA disassembler developed by AVET INS. Handle with care since IDA does not provide "Undo" function. 

ida-brk-comment.py
==================

This plugin lets you manage comments for breakpoints (F2 in debugger module). It can be helpful during larger dynamic analysis whit more than few breakpoint inserted, especially if you collaborate on single disassembly with others.

bios-make-ep.py
===============

This script is obsolete if you are using recent version of IDA. This script helps to correctly relocate BIOS image file in IDA virtual memory to allow proper disassembly. Next it searches for JMP instruction at reset vector address and adds entry point named BIOS_Entry. Please note that the JMP instruction assumption is not valid for all BIOSes since some BIOSes begin with VBINVD instruction at FFFF:FFF0 for example.

mkfc.py
=======

This script helps in analyzing firmwares, option roms and other mobile / embedded devices code by finding unexplored locations and trying to define code and new function at them. On some firmware related images it can help IDA auto analysis to cover more than 90% of unexplored space. Internally it is just a bit more automatic 'C' key press machine.
