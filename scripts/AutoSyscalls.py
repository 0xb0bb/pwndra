# Annotate Linux/Auto-Detected system calls and arguments.
#@author b0bb
#@category Pwn
#@keybinding ctrl 7
#@menupath Analysis.Pwn.Syscalls.Auto
#@toolbar 

from lib.Common import *
from lib.Syscalls import Syscalls
import ghidra.app.util.opinion.ElfLoader as ElfLoader

DEFAULT_ABIS = {
    'mips':   'n32',
    'mips64': 'n64',
    'arm':    'eabi'
}


def run():

    if currentProgram.getExecutableFormat() != ElfLoader.ELF_NAME:
        popup('Not an ELF file, cannot continue')
        return

    arch = getDebianName(currentProgram)
    if arch == None:
        popup('Architecture not defined')
        return

    abi = 'default' if arch not in DEFAULT_ABIS else DEFAULT_ABIS[arch]
    obj = Syscalls(currentProgram, currentSelection, monitor, arch, abi)


run()