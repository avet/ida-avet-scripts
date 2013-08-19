ida-avet-scripts
================

Collection of various scripts for IDA disassembler developed by AVET INS. Handle with care since IDA does not provide "Undo" function. 

ida-brk-comment.py
==================

This plugin lets you manage comments for breakpoints (F2 in debugger module) - this can be helpful during larger dynamic analysis which more than few breakpoint inserted especially if you collaborate on single disassembly with others.

bios-make-ep.py
===============

This script is obsolete if you are using recent version of IDA. Before introduction of BIOS loader in IDA this script helps to correctly relocate BIOS image file in IDA memory to allow disassembly. It later searches for JMP instruction at reset vector and adds entry point named BIOS_Entry. Please note that the JMP instruction assumption is not valid for all BIOSes since some begin with VBINVD instruction at FFFF:FFF0.
