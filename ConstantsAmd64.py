# Find constant values in function calls and returns and update the code to
# display the human readable name(s).
#@author b0bb
#@category Pwn
#@keybinding
#@menupath Analysis.Pwn.Constants.amd64
#@toolbar 

from constants.Constants import Constants
import ghidra.app.util.opinion.ElfLoader as ElfLoader

def run():

    if currentProgram.getExecutableFormat() != ElfLoader.ELF_NAME:
        popup('Not an ELF file, cannot continue')
        return

    arch = 'amd64'
    abi  = 'default'

    Constants(currentProgram, currentSelection, monitor, state, arch, abi)


run()