# Replace Linux/Auto-Detected numeric constants with human readable names.
#@author b0bb
#@category Pwn
#@keybinding ctrl 6
#@menupath Analysis.Pwn.Constants.Auto
#@toolbar 

from lib.Common import *
from lib.Constants import Constants
import ghidra.app.util.opinion.ElfLoader as ElfLoader

DEFAULT_ABIS = {
    'mips':   'n32',
    'mips64': 'n64'
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
    obj = Constants(currentProgram, currentSelection, monitor, state, arch, abi)


run()