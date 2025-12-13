# Go to the entry point (or main() if it exists)
#@author b0bb
#@category Pwn
#@keybinding ctrl m
#@menupath Analysis.Pwn.Utilities.Goto Main
#@toolbar 

from ghidra.app.util.opinion import ElfLoader
from ghidra.app.util.bin import MemoryByteProvider
from ghidra.app.util.bin.format.elf import ElfHeader

from ghidra.program.util import FunctionSignatureFieldLocation
from ghidra.app.plugin.core.navigation.locationreferences import ReferenceUtils
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.util import SymbolicPropogator
from ghidra.program.util.SymbolicPropogator import Value
from ghidra.app.plugin.core.analysis import ConstantPropagationContextEvaluator
from ghidra.app.emulator import EmulatorHelper


# Look for a function called main
def getMainByLabel():

    address  = None
    function = getFirstFunction()
    while function is not None:

        if monitor.isCancelled():
            return doCancel()

        if function.getName() == 'main':
            address = function.getEntryPoint()
            break

        function = getFunctionAfter(function)

    return address


# Get a value for a register (symbolic propagation)
def getRegisterValue(start, call, register):

    symEval  = SymbolicPropogator(currentProgram)
    function = getFunctionContaining(call)

    evaluate = ConstantPropagationContextEvaluator(monitor)

    symEval.flowConstants(
        function.getEntryPoint(),
        function.getBody(),
        evaluate,
        False,
        monitor
    )

    result = symEval.getRegisterValue(call, register)
    if result is not None:
        return result.getValue()

    return None


# Get candidates for a __libc_start_main call
def getStartCalls():

    memory = MemoryByteProvider(currentProgram.getMemory(), currentProgram.getMinAddress())

    # Updated API for Ghidra 11.x
    header = ElfHeader.createElfHeader(memory, None)
    entry = toAddr(header.e_entry())

    if not entry:
        return None

    func = getFunctionContaining(entry)
    blocks = func.getBody()
    calls = []

    for block in blocks:

        start = block.getMinAddress()
        stop  = block.getMaxAddress()
        inst  = getInstructionAt(start)

        while inst is not None:

            if monitor.isCancelled():
                return doCancel()

            addr = inst.getAddress()
            if int(addr.toString(), 16) > int(stop.toString(), 16):
                break

            flowType = inst.getFlowType()
            if flowType == RefType.UNCONDITIONAL_CALL or flowType == RefType.COMPUTED_CALL:
                calls.append((start, addr, inst.getFlows()[0]))

            inst = inst.getNext()

    return calls


def renameFunction(addr, name):

    func = getFunctionContaining(addr)
    if func is None:
        return False

    symbol = func.getSymbol()
    if symbol.getSource() == SourceType.DEFAULT:
        symbol.setName(name, SourceType.USER_DEFINED)


def doCancel():
    print('Operation cancelled')


def run():

    address = getMainByLabel()
    if not address:

        if currentProgram.getExecutableFormat() == ElfLoader.ELF_NAME:

            startCalls = getStartCalls()
            if startCalls is None:
                return

            for start, call, dest in startCalls:

                main = getParam(start, call, 0)
                if main is None:
                    continue

                main = toAddr(main)
                func = getFunctionContaining(main)
                if func is not None:

                    renameFunction(main, 'main')
                    renameFunction(dest, '__libc_start_main')

                    address = main

    if address:
        goTo(address)


run()
