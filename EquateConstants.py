# Find constant values in function calls and returns and update the code to
# display the human readable name(s).
#@author b0bb
#@category Pwn
#@keybinding
#@menupath Analysis.Pwn.Constants.Equate Constants
#@toolbar 

import ghidra.program.model.lang.OperandType as OperandType
import ghidra.program.model.lang.Register as Register
import ghidra.app.emulator.EmulatorHelper as EmulatorHelper
import ghidra.program.model.address.Address as Address
import ghidra.program.model.listing.CodeUnit as CodeUnit
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils as ReferenceUtils
import ghidra.program.util.FunctionSignatureFieldLocation as FunctionSignatureFieldLocation
import ghidra.app.util.opinion.ElfLoader as ElfLoader
import ghidra.program.util.SymbolicPropogator as SymbolicPropogator
import ghidra.program.util.SymbolicPropogator.Value
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator as ConstantPropagationContextEvaluator
import ghidra.program.model.lang.OperandType as OperandType
import ghidra.app.cmd.equate.SetEquateCmd as SetEquateCmd
import ghidra.framework.cmd.Command as Command

import json



# TODO:
#
#   * Find return error codes
#   * Put the constants in their own files so there can be multiple layers depending on arch
#   
#

CONST = {

    # Error Codes
    'EPERM':            1,
    'ENOENT':           2,
    'ESRCH':            3,
    'EINTR':            4,
    'EIO':              5,
    'ENXIO':            6,
    'E2BIG':            7,
    'ENOEXEC':          8,
    'EBADF':            9,
    'ECHILD':          10,
    'EAGAIN':          11,
    'ENOMEM':          12,
    'EACCES':          13,
    'EFAULT':          14,
    'ENOTBLK':         15,
    'EBUSY':           16,
    'EEXIST':          17,
    'EXDEV':           18,
    'ENODEV':          19,
    'ENOTDIR':         20,
    'EISDIR':          21,
    'EINVAL':          22,
    'ENFILE':          23,
    'EMFILE':          24,
    'ENOTTY':          25,
    'ETXTBSY':         26,
    'EFBIG':           27,
    'ENOSPC':          28,
    'ESPIPE':          29,
    'EROFS':           30,
    'EMLINK':          31,
    'EPIPE':           32,
    'EDOM':            33,
    'ERANGE':          34,
    'EDEADLK':         35,
    'ENAMETOOLONG':    36,
    'ENOLCK':          37,
    'ENOSYS':          38,
    'ENOTEMPTY':       39,
    'ELOOP':           40,
    'ENOMSG':          42,
    'EIDRM':           43,
    'ECHRNG':          44,
    'EL2NSYNC':        45,
    'EL3HLT':          46,
    'EL3RST':          47,
    'ELNRNG':          48,
    'EUNATCH':         49,
    'ENOCSI':          50,
    'EL2HLT':          51,
    'EBADE':           52,
    'EBADR':           53,
    'EXFULL':          54,
    'ENOANO':          55,
    'EBADRQC':         56,
    'EBADSLT':         57,
    'EDEADLOCK':       35,
    'EBFONT':          59,
    'ENOSTR':          60,
    'ENODATA':         61,
    'ETIME':           62,
    'ENOSR':           63,
    'ENONET':          64,
    'ENOPKG':          65,
    'EREMOTE':         66,
    'ENOLINK':         67,
    'EADV':            68,
    'ESRMNT':          69,
    'ECOMM':           70,
    'EPROTO':          71,
    'EMULTIHOP':       72,
    'EDOTDOT':         73,
    'EBADMSG':         74,
    'EOVERFLOW':       75,
    'ENOTUNIQ':        76,
    'EBADFD':          77,
    'EREMCHG':         78,
    'ELIBACC':         79,
    'ELIBBAD':         80,
    'ELIBSCN':         81,
    'ELIBMAX':         82,
    'ELIBEXEC':        83,
    'EILSEQ':          84,
    'ERESTART':        85,
    'ESTRPIPE':        86,
    'EUSERS':          87,
    'ENOTSOCK':        88,
    'EDESTADDRREQ':    89,
    'EMSGSIZE':        90,
    'EPROTOTYPE':      91,
    'ENOPROTOOPT':     92,
    'EPROTONOSUPPORT': 93,
    'ESOCKTNOSUPPORT': 94,
    'EOPNOTSUPP':      95,
    'ENOTSUP':         95,
    'EPFNOSUPPORT':    96,
    'EAFNOSUPPORT':    97,
    'EADDRINUSE':      98,
    'EADDRNOTAVAIL':   99,
    'ENETDOWN':       100,
    'ENETUNREACH':    101,
    'ENETRESET':      102,
    'ECONNABORTED':   103,
    'ECONNRESET':     104,
    'ENOBUFS':        105,
    'EISCONN':        106,
    'ENOTCONN':       107,
    'ESHUTDOWN':      108,
    'ETOOMANYREFS':   109,
    'ETIMEDOUT':      110,
    'ECONNREFUSED':   111,
    'EHOSTDOWN':      112,
    'EHOSTUNREACH':   113,
    'EALREADY':       114,
    'EINPROGRESS':    115,
    'ESTALE':         116,
    'EUCLEAN':        117,
    'ENOTNAM':        118,
    'ENAVAIL':        119,
    'EISNAM':         120,
    'EREMOTEIO':      121,
    'EDQUOT':         122,
    'ENOMEDIUM':      123,
    'EMEDIUMTYPE':    124,
    'ECANCELED':      125,
    'ENOKEY':         126,
    'EKEYEXPIRED':    127,
    'EKEYREVOKED':    128,
    'EKEYREJECTED':   129,
}

FUNCTIONS = {

    # file descriptor functions
    'read':      [(0, 'fd')],
    'write':     [(0, 'fd')],
    'close':     [(0, 'fd')],
    'fcntl':     [(0, 'fd')],
    'fsync':     [(0, 'fd')],
    'fdatasync': [(0, 'fd')],
    'ioctl':     [(0, 'fd')],
    'lseek':     [(0, 'fd')],
    'pread':     [(0, 'fd')],
    'pwrite':    [(0, 'fd')],
    'readv':     [(0, 'fd')],
    'writev':    [(0, 'fd')],
    'preadv':    [(0, 'fd')],
    'pwritev':   [(0, 'fd')],
    'preadv2':   [(0, 'fd')],
    'pwritev2':  [(0, 'fd')],
    'fdopen':    [(0, 'fd')],

    # mode_t mode fucntions
    'open': [(1, 'fd_mode')],

    # file mode functions
    'chmod':    [(1, 'file_mode')],
    'fchmod':   [(1, 'file_mode')],
    'fchmodat': [(2, 'file_mode')],

    # signal functions
    'signal':       [(0, 'signal')],
    'kill':         [(1, 'signal')],
    'sigaction':    [(0, 'signal')],
    'sysv_signal':  [(0, 'signal')],
    'sigvec':       [(0, 'signal')],
    'sigmask':      [(0, 'signal')],
    'sigaddset':    [(1, 'signal')],
    'sigdelset':    [(1, 'signal')],
    'sigismember':  [(1, 'signal')],
    'sigqueue':     [(1, 'signal')],
    'siginterrupt': [(0, 'signal')],
    'raise':        [(1, 'signal')],
    'killpg':       [(1, 'signal')],
    'bsd_signal':   [(0, 'signal')],

    # access functions
    'access':     [(1, 'access')],
    'faccessat':  [(2, 'access')],
    'euidaccess': [(1, 'access')],
    'eaccess':    [(1, 'access')],

    # whence functions
    'fseek':   [(2, 'whence')],
    'lseek':   [(2, 'whence')],
    'lseek64': [(2, 'whence')],
    'llseek':  [(2, 'whence')],
    '_llseek': [(4, 'whence')],

    # prot functions
    'mprotect':      [(2, 'prot')],
    'pkey_mprotect': [(2, 'prot')],

    # prot and map_type functions
    'mmap': [
        (2, 'prot'),
        (3, 'map_type'),
    ],

    'mmap2': [
        (2, 'prot'),
        (3, 'map_type'),
    ],

    'remap_file_pages': [
        (2, 'prot'),
        (4, 'map_type'),
    ],
}

ARGS = {

    'ret': {
        'type': 'value',
        'vals': [
            ('EPERM',            1),
            ('ENOENT',           2),
            ('ESRCH',            3),
            ('EINTR',            4),
            ('EIO',              5),
            ('ENXIO',            6),
            ('E2BIG',            7),
            ('ENOEXEC',          8),
            ('EBADF',            9),
            ('ECHILD',          10),
            ('EAGAIN',          11),
            ('ENOMEM',          12),
            ('EACCES',          13),
            ('EFAULT',          14),
            ('ENOTBLK',         15),
            ('EBUSY',           16),
            ('EEXIST',          17),
            ('EXDEV',           18),
            ('ENODEV',          19),
            ('ENOTDIR',         20),
            ('EISDIR',          21),
            ('EINVAL',          22),
            ('ENFILE',          23),
            ('EMFILE',          24),
            ('ENOTTY',          25),
            ('ETXTBSY',         26),
            ('EFBIG',           27),
            ('ENOSPC',          28),
            ('ESPIPE',          29),
            ('EROFS',           30),
            ('EMLINK',          31),
            ('EPIPE',           32),
            ('EDOM',            33),
            ('ERANGE',          34),
            ('EDEADLK',         35),
            ('ENAMETOOLONG',    36),
            ('ENOLCK',          37),
            ('ENOSYS',          38),
            ('ENOTEMPTY',       39),
            ('ELOOP',           40),
            ('ENOMSG',          42),
            ('EIDRM',           43),
            ('ECHRNG',          44),
            ('EL2NSYNC',        45),
            ('EL3HLT',          46),
            ('EL3RST',          47),
            ('ELNRNG',          48),
            ('EUNATCH',         49),
            ('ENOCSI',          50),
            ('EL2HLT',          51),
            ('EBADE',           52),
            ('EBADR',           53),
            ('EXFULL',          54),
            ('ENOANO',          55),
            ('EBADRQC',         56),
            ('EBADSLT',         57),
            ('EDEADLOCK',       35),
            ('EBFONT',          59),
            ('ENOSTR',          60),
            ('ENODATA',         61),
            ('ETIME',           62),
            ('ENOSR',           63),
            ('ENONET',          64),
            ('ENOPKG',          65),
            ('EREMOTE',         66),
            ('ENOLINK',         67),
            ('EADV',            68),
            ('ESRMNT',          69),
            ('ECOMM',           70),
            ('EPROTO',          71),
            ('EMULTIHOP',       72),
            ('EDOTDOT',         73),
            ('EBADMSG',         74),
            ('EOVERFLOW',       75),
            ('ENOTUNIQ',        76),
            ('EBADFD',          77),
            ('EREMCHG',         78),
            ('ELIBACC',         79),
            ('ELIBBAD',         80),
            ('ELIBSCN',         81),
            ('ELIBMAX',         82),
            ('ELIBEXEC',        83),
            ('EILSEQ',          84),
            ('ERESTART',        85),
            ('ESTRPIPE',        86),
            ('EUSERS',          87),
            ('ENOTSOCK',        88),
            ('EDESTADDRREQ',    89),
            ('EMSGSIZE',        90),
            ('EPROTOTYPE',      91),
            ('ENOPROTOOPT',     92),
            ('EPROTONOSUPPORT', 93),
            ('ESOCKTNOSUPPORT', 94),
            ('EOPNOTSUPP',      95),
            ('ENOTSUP',         95),
            ('EPFNOSUPPORT',    96),
            ('EAFNOSUPPORT',    97),
            ('EADDRINUSE',      98),
            ('EADDRNOTAVAIL',   99),
            ('ENETDOWN',       100),
            ('ENETUNREACH',    101),
            ('ENETRESET',      102),
            ('ECONNABORTED',   103),
            ('ECONNRESET',     104),
            ('ENOBUFS',        105),
            ('EISCONN',        106),
            ('ENOTCONN',       107),
            ('ESHUTDOWN',      108),
            ('ETOOMANYREFS',   109),
            ('ETIMEDOUT',      110),
            ('ECONNREFUSED',   111),
            ('EHOSTDOWN',      112),
            ('EHOSTUNREACH',   113),
            ('EALREADY',       114),
            ('EINPROGRESS',    115),
            ('ESTALE',         116),
            ('EUCLEAN',        117),
            ('ENOTNAM',        118),
            ('ENAVAIL',        119),
            ('EISNAM',         120),
            ('EREMOTEIO',      121),
            ('EDQUOT',         122),
            ('ENOMEDIUM',      123),
            ('EMEDIUMTYPE',    124),
            ('ECANCELED',      125),
            ('ENOKEY',         126),
            ('EKEYEXPIRED',    127),
            ('EKEYREVOKED',    128),
            ('EKEYREJECTED',   129),
        ]
    },

    'fd': {
        'type': 'value',
        'vals': [
            ('STDIN_FILENO',  0x00),
            ('STDOUT_FILENO', 0x01),
            ('STDERR_FILENO', 0x02),
        ]
    },

    'file_mode': {
        'type': 'bitwise',
        'vals': [
            ('S_ISUID',  04000),
            ('S_ISGID',  02000),
            ('S_ISVTX',  01000),
            ('S_IREAD',  00400),
            ('S_IWRITE', 00200),
            ('S_IEXEC',  00100),
            ('S_IRGRP',  00040),
            ('S_IWGRP',  00020),
            ('S_IXGRP',  00010),
            ('S_IROTH',  00004),
            ('S_IWOTH',  00002),
            ('S_IXOTH',  00001),
        ]
    },

    'fd_mode': {
        'type': 'bitwise',
        'vals': [
            ('O_RDONLY',    0x000000),
            ('O_WRONLY',    0x000001),
            ('O_RDWR',      0x000002),
            ('O_CREAT',     0x000040),
            ('O_EXCL',      0x000080),
            ('O_NOCTTY',    0x000100),
            ('O_TRUNC',     0x000200),
            ('O_APPEND',    0x000400),
            ('O_NONBLOCK',  0x000800),
            ('O_SYNC',      0x001000),
            ('O_ASYNC',     0x002000),
            ('O_DIRECT',    0x004000),
            ('O_LARGEFILE', 0x008000),
            ('O_DIRECTORY', 0x010000),
            ('O_NOFOLLOW',  0x020000),
            ('O_NOATIME',   0x040000),
            ('O_CLOEXEC',   0x080000),
            ('O_PATH',      0x200000),
            ('O_TMPFILE',   0x400000 | 0x10000),
        ]
    },

    'signal': {
        'type': 'value',
        'vals': [
            ('SIGHUP',    0x01),
            ('SIGINT',    0x02),
            ('SIGQUIT',   0x03),
            ('SIGILL',    0x04),
            ('SIGTRAP',   0x05),
            ('SIGABRT',   0x06),
            ('SIGBUS',    0x07),
            ('SIGFPE',    0x08),
            ('SIGKILL',   0x09),
            ('SIGUSR1',   0x0a),
            ('SIGSEGV',   0x0b),
            ('SIGUSR2',   0x0c),
            ('SIGPIPE',   0x0d),
            ('SIGALRM',   0x0e),
            ('SIGTERM',   0x0f),
            ('SIGSTKFLT', 0x10),
            ('SIGCHLD',   0x11),
            ('SIGCONT',   0x12),
            ('SIGSTOP',   0x13),
            ('SIGTSTP',   0x14),
            ('SIGTTIN',   0x15),
            ('SIGTTOU',   0x16),
            ('SIGURG',    0x17),
            ('SIGXCPU',   0x18),
            ('SIGXFSZ',   0x19),
            ('SIGVTALRM', 0x1a),
            ('SIGPROF',   0x1b),
            ('SIGWINCH',  0x1c),
            ('SIGPOLL',   0x1d),
            ('SIGPWR',    0x1e),
            ('SIGSYS',    0x1f),
            ('SIGRTMIN',  0x22),
            ('SIGRTMAX',  0x40),
        ]
    },

    'access': {
        'type': 'bitwise',
        'vals': [
            ('F_OK', 0),
            ('X_OK', 1),
            ('W_OK', 2),
            ('R_OK', 4),
        ]
    },

    'whence': {
        'type': 'value',
        'vals': [
            ('SEEK_SET',  0),
            ('SEEK_CUR',  1),
            ('SEEK_END',  2),
            ('SEEK_DATA', 3),
            ('SEEK_HOLE', 4),
        ]
    },

    'prot': {
        'type': 'bitwise',
        'vals': [
            ('PROT_NONE',  0x00),
            ('PROT_EXEC',  0x01),
            ('PROT_WRITE', 0x02),
            ('PROT_READ',  0x04),
        ]
    },

    'map_type': {
        'type': 'bitwise',
        'vals': [
            ('MAP_FILE',          0x0000000),
            ('MAP_SHARED',        0x0000001),
            ('MAP_PRIVATE',       0x0000002),
            ('MAP_FIXED',         0x0000010),
            ('MAP_ANONYMOUS.',    0x0000020),
            ('MAP_32BIT',         0x0000040),
            ('MAP_GROWSDOWN',     0x0000100),
            ('MAP_DENYWRITE',     0x0000800),
            ('MAP_EXECUTABLE',    0x0001000),
            ('MAP_LOCKED',        0x0002000),
            ('MAP_NORESERVE',     0x0004000),
            ('MAP_POPULATE',      0x0008000),
            ('MAP_NONBLOCK',      0x0010000),
            ('MAP_STACK',         0x0020000),
            ('MAP_HUGETLB',       0x0040000),
            ('MAP_UNINITIALIZED', 0x4000000),
            ('MAP_HUGE_2MB,',     (21 << 26)),
            ('MAP_HUGE_1GB',      (30 << 26)),
        ]
    }
}


# Get all the call sites inside a given function
def getCalls(func):

    sites = []

    funcManager = currentProgram.getFunctionManager()
    location = FunctionSignatureFieldLocation(currentProgram, func.getEntryPoint())
    addresses = ReferenceUtils.getReferenceAddresses(location, monitor)

    for addr in addresses:

        if monitor.isCancelled():
            return doCancel()

        caller = funcManager.getFunctionContaining(addr)
        if caller is None:
            continue

        if caller.getName() != func.getName():
            sites.append(addr)

    if len(sites) == 0:
        return None

    return sites


# Get a value of a possible constant from a register (through symbolic propogation).
def getRegisterValue(func, call, register):

    symEval  = SymbolicPropogator(currentProgram)
    function = currentProgram.getListing().getFunctionContaining(call)
    evaluate = ConstantPropagationContextEvaluator(True)

    symEval.flowConstants(function.getEntryPoint(), function.getBody(), evaluate, False, monitor)

    result = symEval.getRegisterValue(call, register)
    if result is not None:
        return result.getValue()

    return None


# Get a value of a possible constant from a stack location (through emulation).
def getStackValue(func, call, param):

    inst = currentProgram.getListing().getInstructionAt(call)
    if inst is None:
        return None

    init = call
    curr = inst.getPrevious()

    while curr is not None:

        if monitor.isCancelled():
            return doCancel()

        if curr.getFlowType().toString() != 'FALL_THROUGH':
            break

        init = curr.getAddress()
        curr = curr.getPrevious()

    emulatorHelper = EmulatorHelper(currentProgram)
    emulatorHelper.setBreakpoint(call)
    emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), int(init.toString(), 16))

    stackOffset = (call.getAddressSpace().getMaxAddress().getOffset() >> 1) -  0x7fff;
    emulatorHelper.writeRegister(emulatorHelper.getStackPointerRegister(), stackOffset)

    value = None
    last  = currentProgram.getListing().getCodeUnitAt(init).getPrevious().getAddress()
    while not monitor.isCancelled():

        emulatorHelper.step(monitor)

        if monitor.isCancelled():
            return doCancel()

        address = emulatorHelper.getExecutionAddress()
        current = currentProgram.getListing().getCodeUnitAt(address)

        if address.equals(last):

            # skip bad instructions
            goto = current.getMaxAddress().next()
            #print 'advancing at %s to %s' % (address, goto)
            emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), int(goto.toString(), 16))
            continue

        else:
            last = address

        if address.equals(call):

            start = param.getStackOffset() - param.getLength()
            value = emulatorHelper.readStackValue(start, param.getLength(), True)

            break

    emulatorHelper.clearBreakpoint(call)
    emulatorHelper.dispose()

    return value


# Get a value from a function parameter
def getParameterValue(func, call, n):

    param = func.getParameter(n)
    if param.isRegisterVariable():
        return getRegisterValue(func, call, param.getRegister())
    elif param.isStackVariable():
        return getStackValue(func, call, param)

    return None


# Get a constant string from a given value
def getConstant(kind, value):

    if kind not in ARGS:
        return None

    constants = [] 
    for const in ARGS[kind]['vals']:

        if monitor.isCancelled():
            return doCancel()

        if ARGS[kind]['type'] == 'bitwise':
            if value & const[1] > 0:
                constants.append(const[0])

        elif ARGS[kind]['type'] == 'value':
            if value == const[1]:
                constants.append(const[0])

    return '|'.join(constants) if len(constants) > 0 else None


# Update the representation of a value to a constant
def updateEquates(call, const, value):

    inst = currentProgram.getListing().getInstructionAt(call)
    done = None
    while done is None and inst is not None:

        if monitor.isCancelled():
            return doCancel()

        for i in range(inst.getNumOperands()):

            if monitor.isCancelled():
                return doCancel()

            if inst.getOperandType(i) == OperandType.SCALAR:
                scalar = inst.getScalar(i).getUnsignedValue()
                if scalar == value:

                    cmd = SetEquateCmd(const, inst.getAddress(), i, value)
                    state.getTool().execute(cmd, currentProgram)
                    done = True
                    break


        inst = inst.getPrevious()

        if inst.getFlowType().toString() != 'FALL_THROUGH':
            break


def loadData():

    pass


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

    #print CONST.EPERM
    # import Const
    # global CONST, ARGS, FUNCTIONS

    # CONST     = Const.CONST
    # ARGS      = Const.ARGS
    # FUNCTIONS = Const.FUNCTIONS

    # print CONST.THINGIE

    print getDebianName()

    lang = currentProgram.getLanguage()
    print 'language ID: %s' % lang.getLanguageID()
    print 'processor: %s' % lang.getProcessor()
    print 'version: %s' % lang.getVersion()
    print 'isBigEndian: %s' % lang.isBigEndian()

    desc = lang.getLanguageDescription()
    print desc.getExternalNames('gnu')
    print '---------------'
    print desc.getProcessor()
    print desc.getEndian()
    print desc.getSize()
    print desc.getVariant()
    return

    symEval = SymbolicPropogator(currentProgram)
    symEval.setParamRefCheck(True)
    symEval.setDebug(True)

    for func in currentProgram.getListing().getFunctions(True):

        if monitor.isCancelled():
            return doCancel()

        if func.getName() not in FUNCTIONS:
            continue

        calls = getCalls(func)
        if calls is None:
            continue

        for call in calls:

            if monitor.isCancelled():
                return doCancel()

            for arg in FUNCTIONS[func.getName()]:

                value = getParameterValue(func, call, arg[0])
                if value is None:
                    continue

                const = getConstant(arg[1], value)
                if const is None:
                    continue

                updateEquates(call, const, value)


run()