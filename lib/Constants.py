# Find constant values in function calls and returns and update the code to
# display the human readable name(s).
#@author b0bb
#@category Pwn
#@keybinding ctrl 6
#@menupath Analysis.Pwn.Constants.Auto
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
import json
import os

from Const import Const

CONSTANTS = None
FUNCTIONS = None
ARGUMENTS = None

class Constants:

    state = None
    monitor = None
    currentProgram = None
    currentSelection = None


    # Get all the call sites inside a given function
    def getCalls(self, func):

        sites = []

        funcManager = self.currentProgram.getFunctionManager()
        location = FunctionSignatureFieldLocation(self.currentProgram, func.getEntryPoint())
        addresses = ReferenceUtils.getReferenceAddresses(location, self.monitor)

        for addr in addresses:

            if self.monitor.isCancelled():
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
    def getRegisterValue(self, func, call, register):

        symEval  = SymbolicPropogator(self.currentProgram)
        function = self.currentProgram.getListing().getFunctionContaining(call)
        evaluate = ConstantPropagationContextEvaluator(True)

        symEval.flowConstants(function.getEntryPoint(), function.getBody(), evaluate, False, self.monitor)

        result = symEval.getRegisterValue(call, register)
        if result is not None:
            return result.getValue()

        return None


    # Get a value of a possible constant from a stack location (through emulation).
    def getStackValue(self, func, call, param):

        inst = self.currentProgram.getListing().getInstructionAt(call)
        if inst is None:
            return None

        init = call
        curr = inst.getPrevious()

        while curr is not None:

            if self.monitor.isCancelled():
                return doCancel()

            if curr.getFlowType().toString() != 'FALL_THROUGH':
                break

            init = curr.getAddress()
            curr = curr.getPrevious()

        emulatorHelper = EmulatorHelper(self.currentProgram)
        emulatorHelper.setBreakpoint(call)
        emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), int(init.toString(), 16))

        stackOffset = (call.getAddressSpace().getMaxAddress().getOffset() >> 1) -  0x7fff;
        emulatorHelper.writeRegister(emulatorHelper.getStackPointerRegister(), stackOffset)

        value = None
        last  = self.currentProgram.getListing().getCodeUnitAt(init).getPrevious().getAddress()
        while not self.monitor.isCancelled():

            emulatorHelper.step(self.monitor)

            if self.monitor.isCancelled():
                return doCancel()

            address = emulatorHelper.getExecutionAddress()
            current = self.currentProgram.getListing().getCodeUnitAt(address)

            if address.equals(last):

                # skip bad instructions
                goto = current.getMaxAddress().next()
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
    def getParameterValue(self, func, call, n):

        param = func.getParameter(n)
        if param.isRegisterVariable():
            return self.getRegisterValue(func, call, param.getRegister())
        elif param.isStackVariable():
            return self.getStackValue(func, call, param)

        return None


    # Get a constant string from a given value
    def getConstant(self, kind, value):

        if kind not in ARGUMENTS:
            return None

        constants = [] 
        for const in ARGUMENTS[kind]['vals']:

            if self.monitor.isCancelled():
                return doCancel()

            if ARGUMENTS[kind]['type'] == 'bitwise':
                if value & const[1] > 0:
                    constants.append(const[0])

            elif ARGUMENTS[kind]['type'] == 'value':
                if value == const[1]:
                    constants.append(const[0])

        return '|'.join(constants) if len(constants) > 0 else None


    # Update the representation of a value to a constant
    def updateEquates(self, call, const, value):

        inst = self.currentProgram.getListing().getInstructionAt(call)
        done = None
        while done is None and inst is not None:

            if self.monitor.isCancelled():
                return doCancel()

            for i in range(inst.getNumOperands()):

                if self.monitor.isCancelled():
                    return doCancel()

                if inst.getOperandType(i) == OperandType.SCALAR:
                    scalar = inst.getScalar(i).getUnsignedValue()
                    if scalar == value:

                        cmd = SetEquateCmd(const, inst.getAddress(), i, value)
                        self.state.getTool().execute(cmd, self.currentProgram)
                        done = True
                        break


            inst = inst.getPrevious()

            if inst.getFlowType().toString() != 'FALL_THROUGH':
                break


    # Load data in a multilayered manner
    def loadData(self, kind, arch, abi):

        final  = None
        layers = ['generic', arch, arch+'_'+abi]
        for layer in layers:

            filepath = os.path.dirname(os.path.realpath(__file__))
            filepath = '%s/../data/constants/%s_%s.json' % (filepath, layer, kind)
            filename = os.path.realpath(filepath)

            if os.path.isfile(filename):
                data = None
                with open(filename) as file:
                    data = json.loads(file.read())

                if data is None:
                    continue

                if kind == 'arguments':
                    for name in data:

                        remove = []
                        for index in range(len(data[name]['vals'])):
                            try:
                                value = getattr(CONSTANTS, data[name]['vals'][index][0])
                            except:
                                remove.append(data[name]['vals'][index])
                                continue

                            data[name]['vals'][index][1] = value

                        for item in remove:
                            index = data[name]['vals'].index(item)
                            del data[name]['vals'][index]

                if final is None:
                    final = data
                else:
                    if kind == 'arguments':
                        for index in data:

                            if index not in final:
                                final[index] = data[index]
                            else:
                                for i in data[index]['vals']:
                                    row = data[index]['vals'][i]
                                    if row not in final[index]['vals']:
                                        final[index]['vals'].append(row)

                    elif kind == 'functions':
                        for index in data:

                            if index not in final:
                                final[index] = data[index]
                            else:
                                for i in data[index]:
                                    row = data[index][i]
                                    if row not in final[index]:
                                        final[index].append(row)
                    else:
                        final = data

        return final


    def __init__(self, program, selection, monitor, state, arch, abi='default'):

        self.currentProgram = program
        self.currentSelection = selection
        self.monitor = monitor
        self.state = state

        if self.currentProgram.getExecutableFormat() != ElfLoader.ELF_NAME:
            popup('Not an ELF file, cannot continue')
            return

        global CONSTANTS, ARGUMENTS, FUNCTIONS
        CONSTANTS = Const(arch, abi)
        ARGUMENTS = self.loadData('arguments', arch, abi)
        FUNCTIONS = self.loadData('functions', arch, abi)

        symEval = SymbolicPropogator(self.currentProgram)
        symEval.setParamRefCheck(True)
        symEval.setDebug(True)

        for func in self.currentProgram.getListing().getFunctions(True):

            if self.monitor.isCancelled():
                return doCancel()

            if func.getName() not in FUNCTIONS:
                continue

            calls = self.getCalls(func)
            if calls is None:
                continue

            for call in calls:

                if self.currentSelection is not None:
                    if call < self.currentSelection.getMinAddress():
                        continue
                    if call > self.currentSelection.getMaxAddress():
                        continue

                if self.monitor.isCancelled():
                    return doCancel()

                for arg in FUNCTIONS[func.getName()]:

                    value = self.getParameterValue(func, call, arg[0])
                    if value is None:
                        continue

                    const = self.getConstant(arg[1], value)
                    if const is None:
                        continue

                    self.updateEquates(call, const, value)

