# Go to the entry point (or main() if it exists)
#@author b0bb
#@category Pwn
#@keybinding ctrl m
#@menupath Analysis.Pwn.Utilities.Goto Main
#@toolbar 

import ghidra.app.util.opinion.ElfLoader as ElfLoader
import ghidra.app.util.bin.MemoryByteProvider as MemoryByteProvider
import ghidra.app.util.bin.format.elf.ElfHeader as ElfHeader
import ghidra.program.util.FunctionSignatureFieldLocation as FunctionSignatureFieldLocation
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils as ReferenceUtils
import ghidra.program.model.symbol.RefType as RefType
import ghidra.program.util.SymbolicPropogator as SymbolicPropogator
import ghidra.program.util.SymbolicPropogator.Value
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator as ConstantPropagationContextEvaluator
import ghidra.app.emulator.EmulatorHelper as EmulatorHelper
import ghidra.program.model.symbol.SourceType as SourceType
import ghidra.program.model.data.FunctionDefinitionDataType as FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinitionImpl as ParameterDefinitionImpl
import ghidra.program.model.data.LongDataType as LongDataType
import ghidra.program.model.data.IntegerDataType as IntegerDataType
import ghidra.program.model.data.PointerDataType as PointerDataType
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd as ApplyFunctionSignatureCmd


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

    symEval.flowConstants(function.getEntryPoint(), function.getBody(), evaluate, False, monitor)

    result = symEval.getRegisterValue(call, register)
    if result is not None:
        return result.getValue()

    return None


# Get a value from the stack (emulation)
def getStackValue(start, call, param):

    inst = getInstructionAt(start)
    if inst is None:
        return None

    emulatorHelper = EmulatorHelper(currentProgram)
    emulatorHelper.setBreakpoint(call)
    emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), int(start.toString(), 16))

    stackOffset = (call.getAddressSpace().getMaxAddress().getOffset() >> 1) -  0x7fff;
    emulatorHelper.writeRegister(emulatorHelper.getStackPointerRegister(), stackOffset)
    listing = currentProgram.getListing()

    value = None
    last  = listing.getCodeUnitAt(start).getPrevious().getAddress()
    while not monitor.isCancelled():

        emulatorHelper.step(monitor)

        if monitor.isCancelled():
            return doCancel()

        address = emulatorHelper.getExecutionAddress()
        current = currentProgram.getListing().getCodeUnitAt(address)

        if address.equals(last):

            goto = current.getMaxAddress().next()
            emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), int(goto.toString(), 16))
            continue

        else:

            last = address

        if address.equals(call):

            width = currentProgram.getLanguage().getLanguageDescription().getSize() >> 3
            start = param.getStackOffset() - width
            value = emulatorHelper.readStackValue(start, width, True)

            break

    emulatorHelper.clearBreakpoint(call)
    emulatorHelper.dispose()

    return value


# Get any concrete value for a given paremeter in a __libc_start_main candidate
def getParam(start, call, n):

    inst = getInstructionAt(call)
    addr = inst.getFlows()[0]
    func = getFunctionAt(addr)
    if func is None:
        return None
   
    __libc_start_main_definition = FunctionDefinitionDataType("__libc_start_main")
    main = ParameterDefinitionImpl("main", PointerDataType(), "main")
    argc = ParameterDefinitionImpl("argc", IntegerDataType(), "argc")
    ubp_av = ParameterDefinitionImpl("ubp_av", PointerDataType(), "ubp_av")
    init = ParameterDefinitionImpl("init", PointerDataType(), "init")
    fini = ParameterDefinitionImpl("fini", PointerDataType(), "fini")
    rtld_fini = ParameterDefinitionImpl("rtld_fini", PointerDataType(), "rtld_fini")
    stack_end = ParameterDefinitionImpl("stack_end", PointerDataType(), "stack_end")
    __libc_start_main_definition.setArguments([main, argc, ubp_av, init, fini, rtld_fini, stack_end])
    __libc_start_main_definition.setReturnType(IntegerDataType())
    
    # set the correct signature for __libc_start_main, otherwise getParameter won't find anything
    ApplyFunctionSignatureCmd(addr, __libc_start_main_definition, SourceType.USER_DEFINED).applyTo(currentProgram, monitor)
    func = getFunctionAt(addr)

    param = func.getParameter(n)
    if param is None:
        return None

    if param.isRegisterVariable():
        return getRegisterValue(start, call, param.getRegister().getBaseRegister())
    elif param.isStackVariable():
        return getStackValue(start, call, param)

    return None


# Get candidates for a __libc_start_main call
def getStartCalls():

    memory = MemoryByteProvider(currentProgram.getMemory(), currentProgram.getMinAddress())
    header = ElfHeader(memory, None)
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


# Rename a function that has no imported or user-defined name already
def renameFunction(addr, name):

    func = getFunctionContaining(addr)
    if func is None:
        return False

    symbol = func.getSymbol()
    if symbol.getSource() == SourceType.DEFAULT:
        symbol.setName(name, SourceType.USER_DEFINED)


# Show a nice cancel message in the console log
def doCancel():

    print 'Operation cancelled'


# Entry point for script
def run():

    address = getMainByLabel()
    if not address:

        if currentProgram.getExecutableFormat() == ElfLoader.ELF_NAME:

            startCalls = getStartCalls()
            if startCalls is None:
                return

            for startCall in startCalls:

                start, call, dest = startCall

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
