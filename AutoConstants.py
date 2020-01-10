# Replace Linux/Auto-Detected numeric constants with human readable names.
#@author b0bb
#@category Pwn
#@keybinding ctrl 6
#@menupath Analysis.Pwn.Constants.Auto
#@toolbar 

from constants.Constants import Constants
import ghidra.app.util.opinion.ElfLoader as ElfLoader

DEFAULT_ABIS = {
    'mips':   'n32',
    'mips64': 'n64'
}


def getDebianName():

    lang = currentProgram.getLanguage()
    desc = lang.getLanguageDescription()

    processor = desc.getProcessor().toString()
    endianess = desc.getEndian().toString()
    width = desc.getSize()
    variant = desc.getVariant()

    name = None
    if processor == 'x86':
        name = 'i386' if width == 32 else 'amd64'

    if processor == 'sparc':
        name = 'sparc' if width == 32 else 'sparc64'

    if processor == 'AARCH64':
        name = 'aarch64'

    if processor == 'pa-risc':
        name = 'hppa'

    if processor == '68000':
        name = 'm68k'

    if processor == 'ARM':
        name = 'arm'

    if processor == 'SuperH':
        name = 'sh'

    if processor == 'SuperH4':
        name = 'sh4'

    if processor == 'PowerPC':
        name = 'powerpc' if width == 32 else 'powerpc64'

    if processor == 'MIPS':
        if width == 64:
            name = 'mips' if '32' in variant else 'mips64'
        else:
            name = 'mips'

    return name


def run():

    if currentProgram.getExecutableFormat() != ElfLoader.ELF_NAME:
        popup('Not an ELF file, cannot continue')
        return

    arch = getDebianName()
    if arch == None:
        popup('Architecture not defined')
        return

    abi = 'default' if arch not in DEFAULT_ABIS else DEFAULT_ABIS[arch]
    obj = Constants(currentProgram, currentSelection, monitor, state, arch, abi)


run()