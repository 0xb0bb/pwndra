import ghidra.app.util.opinion.ElfLoader as ElfLoader
import ghidra.program.util.SymbolicPropogator as SymbolicPropogator
import ghidra.program.util.SymbolicPropogator.Value
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator as ConstantPropagationContextEvaluator
import ghidra.program.flatapi.FlatProgramAPI as FlatProgramAPI
import json
import os

SYSCALLS  = None
FUNCTIONS = None
ARCHS = {

    'amd64': {
        'default': {
            'reg': 'RAX',
            'arg': [
                'RDI', 'RSI', 'RDX',
                'R10', 'R8',  'R9'
            ],

            'ins': [
                {
                    'interrupt': 'SYSCALL',
                    'endian':    'little',
                    'opcode':    '\\x0f\\x05'
                }
            ]
        }
    },

    'i386': {
        'default': {
            'reg': 'EAX',
            'arg': [
                'EBX', 'ECX', 'EDX',
                'ESI', 'EDI', 'EBP'
            ],

            'ins': [
                {
                    'interrupt': 'INT 0x80',
                    'endian':    'little',
                    'opcode':    '\\xcd\\x80'
                },
                {
                    'interrupt': 'CALL dword ptr GS:[0x10]',
                    'endian':    'little',
                    'opcode':    '\\x65\\xff\\x15\\x10\\x00\\x00\\x00'
                }
            ]
        }
    },

    'aarch64': {
        'default': {
            'reg': 'x8',
            'arg': [
                'x0', 'x1', 'x2',
                'x3', 'x4', 'x5'
            ],

            'ins': [
                {
                    'interrupt': 'svc 0x0',
                    'endian':    'little',
                    'opcode':    '\\x01\\x00\\x00\\xd4'
                },
                {
                    'interrupt': 'svc 0x0',
                    'endian':    'big',
                    'opcode':    '\\xd4\\x00\\x00\\x01'
                }
            ]
        }
    },

    'm68k': {
        'default': {
            'reg': 'D0',
            'arg': [
                'D1', 'D2', 'D3',
                'D4', 'D5', 'A0'
            ],

            'ins': [
                {
                    'interrupt': 'trap #0x0',
                    'endian':    'big',
                    'opcode':    '\\x4e\\x40'
                }
            ]
        }
    },

    'hppa': {
        'default': {
            'reg': 'r20',
            'arg': [
                'r26', 'r25', 'r24',
                'r23', 'r22', 'r21'
            ],

            'ins': [
                {
                    'interrupt': 'BE,L 0x100(sr2,r0)',
                    'endian':    'big',
                    'opcode':    '\\xe4\\x00\\x82\\x00'
                }
            ]
        }
    },

    'powerpc': {
        'default': {
            'reg': 'r0',
            'arg': [
                'r3', 'r4', 'r5',
                'r6', 'r7', 'r8',
                'r9'
            ],

            'ins': [
                {

                    'interrupt': 'sc 0x0',
                    'endian':    'little',
                    'opcode':    '\\x02\\x00\\x00\\x44'
                },
                {

                    'interrupt': 'sc 0x0',
                    'endian':    'big',
                    'opcode':    '\\x44\\x00\\x00\\x02'
                }
            ]
        }
    },

    'powerpc64': {
        'default': {
            'reg': 'r0',
            'arg': [
                'r3', 'r4', 'r5',
                'r6', 'r7', 'r8'
            ],

            'ins': [
                {

                    'interrupt': 'sc 0x0',
                    'endian':    'little',
                    'opcode':    '\\x02\\x00\\x00\\x44'
                },
                {

                    'interrupt': 'sc 0x0',
                    'endian':    'big',
                    'opcode':    '\\x44\\x00\\x00\\x02'
                }
            ]
        }
    },

    'mips': {

        'o32': {
            'reg': 'v0',
            'arg': [
                'a0', 'a1', 'a2',
                'a3'
            ],

            'ins': [
                {

                    'interrupt': 'syscall',
                    'endian':    'little',
                    'opcode':    '\\x0c\\x00\\x00\\x00'
                },
                {

                    'interrupt': 'syscall',
                    'endian':    'big',
                    'opcode':    '\\x00\\x00\\x00\\x0c'
                }
            ]
        },

        'n32': {
            'reg': 'v0',
            'arg': [
                'a0', 'a1', 'a2',
                'a3', 'a4', 'a5'
            ],

            'ins': [
                {

                    'interrupt': 'syscall',
                    'endian':    'little',
                    'opcode':    '\\x0c\\x00\\x00\\x00'
                },
                {

                    'interrupt': 'syscall',
                    'endian':    'big',
                    'opcode':    '\\x00\\x00\\x00\\x0c'
                }
            ]
        }
    },

    'mips64': {

        'n64': {
            'reg': 'v0',
            'arg': [
                'a0', 'a1', 'a2',
                'a3', 'a4', 'a5'
            ],

            'ins': [
                {

                    'interrupt': 'syscall',
                    'endian':    'little',
                    'opcode':    '\\x0c\\x00\\x00\\x00'
                },
                {

                    'interrupt': 'syscall',
                    'endian':    'big',
                    'opcode':    '\\x00\\x00\\x00\\x0c'
                }
            ]
        }
    },

    'arm': {
        'eabi': {
            'reg': 'r7',
            'arg': [
                'r0', 'r1', 'r2',
                'r3', 'r4', 'r5',
                'r6'
            ],

            'ins': [
                {

                    'interrupt': 'svc 0x0',
                    'endian':    'little',
                    'opcode':    '\\x00\\xdf'
                },
                {

                    'interrupt': 'svc 0x0',
                    'endian':    'big',
                    'opcode':    '\\xdf\\x00'
                },
                {

                    'interrupt': 'swi 0x0',
                    'endian':    'little',
                    'opcode':    '\\x00\\x00\\x00\\xef'
                },
                {

                    'interrupt': 'swi 0x0',
                    'endian':    'big',
                    'opcode':    '\\xef\\x00\\x00\\x00'
                }
            ]
        }
    },

    'sh': {
        'default': {
            'reg': 'r3',
            'arg': [
                'r4', 'r5', 'r6',
                'r7', 'r0', 'r1',
                'r2'
            ],

            'ins': [
                {

                    'interrupt': 'trapa #0x10',
                    'endian':    'little',
                    'opcode':    '\\x10\\xc3'
                },
                {

                    'interrupt': 'trapa #0x10',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x10'
                },
                {

                    'interrupt': 'trapa #0x11',
                    'endian':    'little',
                    'opcode':    '\\x11\\xc3'
                },
                {

                    'interrupt': 'trapa #0x11',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x11'
                },
                {

                    'interrupt': 'trapa #0x12',
                    'endian':    'little',
                    'opcode':    '\\x12\\xc3'
                },
                {

                    'interrupt': 'trapa #0x12',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x12'
                },
                {

                    'interrupt': 'trapa #0x13',
                    'endian':    'little',
                    'opcode':    '\\x13\\xc3'
                },
                {

                    'interrupt': 'trapa #0x13',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x13'
                },
                {

                    'interrupt': 'trapa #0x14',
                    'endian':    'little',
                    'opcode':    '\\x14\\xc3'
                },
                {

                    'interrupt': 'trapa #0x14',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x14'
                },
                {

                    'interrupt': 'trapa #0x15',
                    'endian':    'little',
                    'opcode':    '\\x15\\xc3'
                },
                {

                    'interrupt': 'trapa #0x15',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x15'
                },
                {

                    'interrupt': 'trapa #0x16',
                    'endian':    'little',
                    'opcode':    '\\x16\\xc3'
                },
                {

                    'interrupt': 'trapa #0x16',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x16'
                },
                {

                    'interrupt': 'trapa #0x17',
                    'endian':    'little',
                    'opcode':    '\\x17\\xc3'
                },
                {

                    'interrupt': 'trapa #0x17',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x17'
                }
            ]
        }
    },

    'sh4': {
        'default': {
            'reg': 'r3',
            'arg': [
                'r4', 'r5', 'r6',
                'r7', 'r0', 'r1',
                'r2'
            ],

            'ins': [
                {

                    'interrupt': 'trapa #0x10',
                    'endian':    'little',
                    'opcode':    '\\x10\\xc3'
                },
                {

                    'interrupt': 'trapa #0x10',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x10'
                },
                {

                    'interrupt': 'trapa #0x11',
                    'endian':    'little',
                    'opcode':    '\\x11\\xc3'
                },
                {

                    'interrupt': 'trapa #0x11',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x11'
                },
                {

                    'interrupt': 'trapa #0x12',
                    'endian':    'little',
                    'opcode':    '\\x12\\xc3'
                },
                {

                    'interrupt': 'trapa #0x12',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x12'
                },
                {

                    'interrupt': 'trapa #0x13',
                    'endian':    'little',
                    'opcode':    '\\x13\\xc3'
                },
                {

                    'interrupt': 'trapa #0x13',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x13'
                },
                {

                    'interrupt': 'trapa #0x14',
                    'endian':    'little',
                    'opcode':    '\\x14\\xc3'
                },
                {

                    'interrupt': 'trapa #0x14',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x14'
                },
                {

                    'interrupt': 'trapa #0x15',
                    'endian':    'little',
                    'opcode':    '\\x15\\xc3'
                },
                {

                    'interrupt': 'trapa #0x15',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x15'
                },
                {

                    'interrupt': 'trapa #0x16',
                    'endian':    'little',
                    'opcode':    '\\x16\\xc3'
                },
                {

                    'interrupt': 'trapa #0x16',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x16'
                },
                {

                    'interrupt': 'trapa #0x17',
                    'endian':    'little',
                    'opcode':    '\\x17\\xc3'
                },
                {

                    'interrupt': 'trapa #0x17',
                    'endian':    'big',
                    'opcode':    '\\xc3\\x17'
                }
            ]
        }
    },

    'sparc': {
        'default': {
            'reg': 'g1',
            'arg': [
                'o0', 'o1', 'o2',
                'o3', 'o4', 'o5'
            ],

            'ins': [
                {

                    'interrupt': 'ta ',
                    'endian':    'little',
                    'opcode':    '\\x10\\x20\\xd0\\x91'
                },
                {

                    'interrupt': 'ta ',
                    'endian':    'big',
                    'opcode':    '\\x91\\xd0\\x20\\x10'
                }
            ]
        }
    },

    'sparc64': {
        'default': {
            'reg': 'g1',
            'arg': [
                'o0', 'o1', 'o2',
                'o3', 'o4', 'o5'
            ],

            'ins': [
                {

                    'interrupt': 'ta ',
                    'endian':    'little',
                    'opcode':    '\\x6d\\x20\\xd0\\x91'
                },
                {

                    'interrupt': 'ta ',
                    'endian':    'big',
                    'opcode':    '\\x91\\xd0\\x20\\x6d'
                }
            ]
        }
    }
}

class Syscalls:

    flatProgram = None
    symEval = None
    monitor = None
    currentProgram = None
    currentSelection = None


    # Find all the places where the system call appears
    def getSyscalls(self, opcode, mnemonic):

        calls = []
        listing = self.currentProgram.getListing()
        locations = self.flatProgram.findBytes(self.currentProgram.getMinAddress(), opcode, 8192)

        for addr in locations:

            if self.monitor.isCancelled():
                return self.doCancel()

            ins = listing.getCodeUnitAt(addr)
            if ins is None:
                continue

            if mnemonic in ins.toString():
                calls.append(addr)

        return calls


    # Get a register value at a certain address through symbolic propagation
    def getRegisterValue(self, addr, register):

        function = self.currentProgram.getListing().getFunctionContaining(addr)
        evaluate = ConstantPropagationContextEvaluator(self.monitor)

        if function is None:
            return None

        self.symEval.flowConstants(function.getEntryPoint(), function.getBody(), evaluate, False, self.monitor)

        result = self.symEval.getRegisterValue(addr, register)
        if result is not None:
            return result.getValue()

        return None


    # Get a function signature
    def getSignature(self, name, data):

        return '%s %s(%s)' % (data['ret'], name, ', '.join(data['args']))


    # Mark the positions of arguments for the current syscall
    def markArguments(self, args, addr, data):

        listing = self.currentProgram.getListing()
        function = self.currentProgram.getListing().getFunctionContaining(addr)
        evaluate = ConstantPropagationContextEvaluator(self.monitor)

        if function is None:
            return None

        ins = listing.getCodeUnitAt(addr)
        if ins is None:
            return

        for block in function.getBody():
            if addr >= block.getMinAddress() and addr <= block.getMaxAddress():
                base = block.getMinAddress()
                break

        start = ins.getAddress()
        curr = ins.getPrevious()
        while curr != None:

            if curr.getFlowType().toString() != 'FALL_THROUGH':
                break

            start = curr.getAddress()
            if curr.getAddress().equals(base):
                break

            curr = curr.getPrevious()

        args = args[0:len(data['args'])]
        affected = {}
        for arg in args:
            affected[arg] = {
                'addr': None,
                'comment': data['args'][args.index(arg)]
            }

        curr = listing.getCodeUnitAt(start)
        while curr != None:

            addy = curr.getAddress()
            if curr.getAddress().equals(addr):
                break

            for which in curr.getResultObjects():
                if which.toString() in affected:
                    affected[which.toString()]['addr'] = addy

            curr = curr.getNext()

        for which in affected:
            if affected[which]['addr'] is None:
                continue
            self.flatProgram.setPostComment(affected[which]['addr'], affected[which]['comment'])


    # Cancel message
    def doCancel(self):

        print 'Operation cancelled'


    # Load data in a multilayered manner
    def loadData(self, kind, arch, abi):

        final  = None
        layers = ['generic', arch, arch+'_'+abi]
        for layer in layers:

            filepath = os.path.dirname(os.path.realpath(__file__))
            filepath = '%s/../data/syscalls/%s_%s.json' % (filepath, layer, kind)
            filename = os.path.realpath(filepath)

            if os.path.isfile(filename):
                data = None
                with open(filename) as file:
                    data = json.loads(file.read())

                if data is None:
                    continue

                if final is None:
                    final = data

        return final


    def __init__(self, program, selection, monitor, arch, abi='default'):

        self.currentProgram = program
        self.currentSelection = selection
        self.monitor = monitor
        self.flatProgram = FlatProgramAPI(program, monitor)
        self.symEval  = SymbolicPropogator(self.currentProgram)

        if self.currentProgram.getExecutableFormat() != ElfLoader.ELF_NAME:
            popup('Not an ELF file, cannot continue')
            return

        if arch not in ARCHS:
            popup('Architecture not defined')
            return

        if abi not in ARCHS[arch]:
            popup('ABI not defined')
            return

        global SYSCALLS, FUNCTIONS
        SYSCALLS  = self.loadData('syscalls', arch, abi)
        FUNCTIONS = self.loadData('functions', arch, abi)

        data = ARCHS[arch][abi]
        endian = self.currentProgram.getLanguage().getLanguageDescription().getEndian().toString()

        for row in data['ins']:

            if row['endian'] != endian:
                continue

            calls = self.getSyscalls(row['opcode'], row['interrupt'])
            for call in calls:

                if self.currentSelection is not None:
                    if call < self.currentSelection.getMinAddress():
                        continue
                    if call > self.currentSelection.getMaxAddress():
                        continue

                reg = self.currentProgram.getRegister(data['reg'])
                res = self.getRegisterValue(call, reg)

                if res is None:
                    continue

                res = str(res)
                if res not in SYSCALLS:
                    continue

                syscall = SYSCALLS[res]
                comment = syscall

                if syscall in FUNCTIONS:
                    comment = self.getSignature(syscall, FUNCTIONS[syscall])
                    self.markArguments(data['arg'], call, FUNCTIONS[syscall])

                self.flatProgram.setEOLComment(call, comment)
                self.flatProgram.createBookmark(call, 'Syscall', 'Found %s -- %s' % (syscall, comment))

