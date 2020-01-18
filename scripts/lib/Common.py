def getDebianName(currentProgram):

    lang = currentProgram.getLanguage()
    desc = lang.getLanguageDescription()

    processor = desc.getProcessor().toString().lower()
    endianess = desc.getEndian().toString()
    width = desc.getSize()
    variant = desc.getVariant()

    name = None
    if processor == 'x86':
        name = 'i386' if width == 32 else 'amd64'

    if processor == 'sparc':
        name = 'sparc' if width == 32 else 'sparc64'

    if processor == 'aarch64':
        name = 'aarch64'

    if processor == 'pa-risc':
        name = 'hppa'

    if processor == '68000':
        name = 'm68k'

    if processor == 'arm':
        name = 'arm'

    if processor == 'superh':
        name = 'sh'

    if processor == 'superh4':
        name = 'sh4'

    if processor == 'powerpc':
        name = 'powerpc' if width == 32 else 'powerpc64'

    if processor == 'mips':
        if width == 64:
            name = 'mips' if '32' in variant else 'mips64'
        else:
            name = 'mips'

    return name
