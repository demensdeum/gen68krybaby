import os
import sys
import binascii

if len(sys.argv) < 3:
    print("Usage python3 gen68krybaby.py genesisRom.bin output.disasm")
    exit(1)

def convertLine(line):
    output = line.replace("4E B9", "_JUMP")
    output = output.replace("4E 71", "_NOP_")
    return output

filepath = sys.argv[1]
rom = open(filepath, 'rb')
content = rom.read()
rom.close()
hexString = str(binascii.hexlify(content))[2:-1]
disasmFilePath = sys.argv[2]
disasm = open(disasmFilePath, 'w')
outputLine = "\n\t\t\t\t\t\t ROM HEADER:\n\n"
outputLine += "0x00000000 | "
for index, char in enumerate(hexString):
    outputLine += str(char).upper()
    if index % 2 == 1:
        outputLine += " "
    if index % 32 == 31 and index != len(hexString)-1:
        outputLine += "\n"
        value = int(index / 2) + 1
        if value == 512:
            outputLine += "\n\t\t\t\t\t\t RESET:\n\n"
        padding = 10
        outputLine += f"{value:#0{padding}x}".upper()
        outputLine += str(" | ")
        disasm.write(convertLine(outputLine))
        outputLine = ""
        
disasm.close()

exit(0)