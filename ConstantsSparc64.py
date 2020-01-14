# Replace Solaris/Sparc64 numeric constants with human readable names.
#@author b0bb
#@category Pwn
#@keybinding
#@menupath Analysis.Pwn.Constants.sparc64
#@toolbar 

from lib.Constants import Constants
import ghidra.app.util.opinion.ElfLoader as ElfLoader

def run():

    if currentProgram.getExecutableFormat() != ElfLoader.ELF_NAME:
        popup('Not an ELF file, cannot continue')
        return

    arch = 'sparc64'
    abi  = 'default'

    Constants(currentProgram, currentSelection, monitor, state, arch, abi)


run()