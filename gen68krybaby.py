import os
import sys
import binascii

if len(sys.argv) < 3:
    print("Usage python3 gen68krybaby.py genesisRom.bin output.disasm")
    exit(1)

filepath = sys.argv[1]
rom = open(filepath, 'rb')
content = rom.read()
rom.close()
hexString = str(binascii.hexlify(content))[2:-1]
disasmFilePath = sys.argv[2]
disasm = open(disasmFilePath, 'w')
disasm.write("0x00000000 | ")
for index, char in enumerate(hexString):
    disasm.write(str(char).upper())
    if index % 2 == 1:
        disasm.write(" ")
    if index % 32 == 31 and index != len(hexString)-1:
        disasm.write("\n")
        value = int(index / 2) + 1
        padding = 10
        disasm.write(f"{value:#0{padding}x}".upper())
        disasm.write(str(" | "))
        
disasm.close()

exit(0)