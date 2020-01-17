# Annotate Linux/MIPS (n64) system calls and arguments.
#@author b0bb
#@category Pwn
#@keybinding
#@menupath Analysis.Pwn.Syscalls.mips.n64
#@toolbar 

from lib.Syscalls import Syscalls
import ghidra.app.util.opinion.ElfLoader as ElfLoader

def run():

    if currentProgram.getExecutableFormat() != ElfLoader.ELF_NAME:
        popup('Not an ELF file, cannot continue')
        return

    arch = 'mips64'
    abi  = 'n64'

    obj = Syscalls(currentProgram, currentSelection, monitor, arch, abi)


run()