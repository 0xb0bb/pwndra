# Convert an operand to characters
#@author b0bb
#@category Pwn
#@keybinding shift r
#@menupath Analysis.Pwn.Utilities.Convert to Char
#@toolbar 

import ghidra.app.cmd.equate.SetEquateCmd as SetEquateCmd
import ghidra.program.util.OperandFieldLocation as OperandFieldLocation
import ghidra.program.model.lang.OperandType as OperandType

def run():

    if type(currentLocation) is not OperandFieldLocation:
        return

    addr = currentLocation.getAddress()
    inst = currentProgram.getListing().getInstructionAt(addr)
    opin = currentLocation.getOperandIndex()

    if inst.getOperandType(opin) == OperandType.SCALAR:

        string = ''
        scalar = inst.getScalar(opin)
        bvalue = scalar.byteArrayValue()

        if not currentProgram.getLanguage().isBigEndian():
            bvalue.reverse()

        for value in bvalue:
            if value < 0x20 or value > 0x7e:
                string += '\\x%02x' % value
            else:
                string += chr(value)

        cmd = SetEquateCmd('"%s"' % string, addr, opin, scalar.getValue())
        state.getTool().execute(cmd, currentProgram)


run()