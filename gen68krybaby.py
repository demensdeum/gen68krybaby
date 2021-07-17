import os
import sys
import binascii
from enum import Enum

GenericAsmFileSignature = "asm"
DisasmFileSignature = "gen68KryBabyDisasm"
AsmFileSignature = "gen68KryBabyAsm.bin"
RomHeaderLabel = "ROM HEADER"
SubroutineSignature = "SUBROUTINE_"

def HexAddress(address):
    padding = 10
    output = f"{address:#0{padding}x}"
    return output

class Constants(Enum):
    EntryPoint = int(0x200)

class State(Enum):
    Data = 1
    Operations = 2

class Word:
    def __init__(self, data, address):
        self.data = data
        self.address = address

class WordsReader:
    def __init__(self, filepath):
        rom = open(filepath, 'rb')
        content = rom.read()
        rom.close()
        self.hexString = str(binascii.hexlify(content))[2:-1]
        self.cursor = -1

    def nextWord(self):
        self.cursor += 1
        address = int(self.cursor / 2)
        if self.cursor >= len(self.hexString):
            return None
        lhs = self.hexString[self.cursor]
        rhs = ""
        self.cursor += 1
        if self.cursor < len(self.hexString):
            rhs = self.hexString[self.cursor]
        data = f"{lhs}{rhs}"
        return Word(data, address)

class DisassemblerToChunkReaderAdapter:
    def __init__(self, chunkReader):
        self.wordsReader = chunkReader

    def fetchLongWordMemoryAddress(self):
        output = "0x"
        for i in range(4):
            output += self.wordsReader.nextWord().data
        return output

class Disassembler:
    def __init__(self, input, output):
        self.subroutinesAdresses = {Constants.EntryPoint.value}
        self.segmentStartAddress = None
        self.lhsChunk = None
        self.rhsChunk = None
        self.state = State.Data
        self.input = input
        self.output = output

    def addSubroutineAddress(self, address):
        self.subroutinesAdresses.add(int(address, base=16))

    def disasmOperationWords(self):
        output = f"{self.lhsChunk.data}{self.rhsChunk.data}".upper()

        self.lhsChunk = None
        self.rhsChunk = None

        output = output.replace("4EB9", "JSR")
        output = output.replace("4E71", "NOP")
        output = output.replace("4E75", "RTS")
        output = output.replace("4E73", "RTE")
        output = output.replace("4E77", "RTR")
        output = output.replace("2079", "MOVEA.L,A0")
        output = output.replace("2279", "MOVEA.L,A1")

        if output == "JSR":
            address = self.input.fetchLongWordMemoryAddress()
            self.addSubroutineAddress(address)
            output = f"JSR {SubroutineSignature}{address}\n"
            return output

        elif output == "MOVEA.L,A0":
            address = self.input.fetchLongWordMemoryAddress()
            output = f"MOVEA.L {address},A0\n"
            return output

        elif output == "MOVEA.L,A1":
            address = self.input.fetchLongWordMemoryAddress()
            output = f"MOVEA.L {address},A1\n"
            return output

        elif output == "NOP":
            output = "NOP\n"
            return output

        elif output == "RTS":
            output = "RTS\n"
            return output

        elif output == "RTE":
            output = "RTE\n"
            return output

        elif output == "RTR":
            output = "RTR\n"
            return output

        return f"{output}\n"

    def disasm(self, chunk):
        if self.segmentStartAddress == None:
            self.segmentStartAddress = chunk.address
            self.output.write(f"{RomHeaderLabel}:\n")

        if chunk.address in self.subroutinesAdresses:
            if self.state == State.Data:
                self.output.write("\n")
            self.state = State.Operations
            self.output.write(f"\nSUBROUTINE_{HexAddress(chunk.address)}:\n")

        if self.state == State.Operations:
            if self.lhsChunk == None:
                self.lhsChunk = chunk

            elif self.rhsChunk == None:
                self.rhsChunk = chunk
                output = self.disasmOperationWords()
                self.output.write(f"\t\t{output}")
        else:
            self.output.write(f" {chunk.data}")

class Assembler:
    class Subroutine:
        def __init__(self, label, address):
            self.label = label
            self.address = address    
    
    def __init__(self, input, output):
        self.input = input
        self.output = output
        self.state = State.Data
        self.subroutinesPointers = list()
        self.subroutines = list()

    def writeChunkToHex(self, chunk):
        hexString = f"0x{chunk}"
        outputInt = int(hexString, 16)
        outputBytes = bytes([outputInt])
        self.output.write(outputBytes)

    def operationToHex(self, operationLine):
        components = operationLine.split(" ")
        if len(components) < 1:
            return

        operation = components[0]
        if operation == "RTS":
            self.toHex("4E75")

        elif operation == "NOP":
            self.toHex("4E71")

        elif operation == "RTE":
            self.toHex("4E73")

        elif operation == "JSR":
            if len(components) != 2:
                print(f"Incorrect JSR operation count ({len(components)}): {operationLine}; len: {len(operationLine)}; waaa! waa!!")
                exit(1)
            else:
                address = components[1]
                self.jsrToHex(address)

        elif operation == "MOVEA.L":
            if len(components) != 2:
                print(f"Incorrect JSR operation count ({len(components)}): {operationLine}; len: {len(operationLine)}; waaa! waa!!")
                exit(1)
            else:
                arguments = components[1]
                if len(arguments) != 13:
                    print(f"Incorrect MOVEA.L operation arguments ({len(arguments)}) != 13: {arguments}; waaa! waa!!")
                    exit(1)
                else:
                    address = arguments[2:10]
                    register = arguments[11:]
                    self.moveaToHex(address, register)

        else:
            print(f"Unknown operation: {operationLine}; len: {len(operationLine)}; waa! waa!!!")
            exit(1)

    def cursor(self):
        return self.output.tell()

    def addressToHex(self, address):
        self.toHex(address[0:4])
        self.toHex(address[4:8])

    def moveaToHex(self, address, register):
        if register == "A0":
            self.toHex("2079")
        elif register == "A1":
            self.toHex("2279")
        self.addressToHex(address)

    def jsrToHex(self, address):
        self.toHex("4EB9")
        if address.startswith(f"{SubroutineSignature}0x") and len(address) == len(f"{SubroutineSignature}0x00000000"):
            hexAddress = address[len(f"{SubroutineSignature}0x"):]
            self.addressToHex(hexAddress)
        elif address.startswith(SubroutineSignature):
            self.subroutinesPointers.append(self.Subroutine(address, self.cursor()))
            hexAddress = HexAddress(len(self.subroutinesPointers) - 1)[2:]
            self.addressToHex(hexAddress)
        else:
            print(f"Incorrect JSR operation address, must start with {SubroutineSignature} or as hex address (0x00000200 for example); current address: {address}; waa!!")
            exit(1)

    def toHex(self, line):
        if len(line) == 4:
            self.toHex(line[:2])
            self.toHex(line[2:])
        elif len(line) == 2:
            chunk = line
            self.writeChunkToHex(chunk)
        else:
            self.operationToHex(line)

    def assembly(self, line):
        if line == f"{RomHeaderLabel}:\n":
            self.state = State.Data
            return
        elif line.startswith(SubroutineSignature):
            self.state = State.Operations
            label = line.strip()[:-1]
            self.subroutines.append(self.Subroutine(label, self.cursor()))
            return
        elif len(line.strip()) < 1:
            return

        line = line.strip()
        line = line.split(";")
        if len(line) > 2:
            print(f"line: {line} is incorrect, len({len(line)}) > 2, must be less 2; waaa!!!!")
            exit(1)
        if len(line) < 1:
            print(f"line: {line} is incorrect, len({len(line)}) < 1, must be more than 0; waaa!!")
            exit(1)
        line = line[0]

        if self.state == State.Data:
            chunks = line.split(" ")
            for chunk in chunks:
                if len(chunk) == 2:
                    hexString = f"0x{chunk}"
                    outputInt = int(hexString, 16)
                    outputBytes = bytes([outputInt])
                    self.output.write(outputBytes)
        elif self.state == State.Operations:
            self.toHex(line)
            
    def mapPointersToSubroutines(self):
        for pointer in self.subroutinesPointers:
            self.output.seek(pointer.address)
            resolved = False
            for subroutine in self.subroutines:
                if subroutine.label == pointer.label:
                    hexAddress = HexAddress(subroutine.address)[2:]
                    self.addressToHex(hexAddress)
                    resolved = True
            
            if resolved == False:
                print(f"Cannot resolve subroutine: {pointer.label}!! waaa!!!!")
                exit(1)

def assembly(filePath):
    global AsmFileSignature
    disasm = open(filePath, "r")
    asmFilePath = f"{filePath}.{AsmFileSignature}"
    asm = open(asmFilePath, "wb")
    assembler = Assembler(None, asm)
    for line in disasm:
        assembler.assembly(line)
    assembler.mapPointersToSubroutines()
    disasm.close()
    asm.close()

def disassembly(filePath):
    global DisasmFileSignature
    disasmFilePath = f"{filePath}.{DisasmFileSignature}"
    disasm = open(disasmFilePath, 'w')
    chunkReader = WordsReader(filePath)
    adapter = DisassemblerToChunkReaderAdapter(chunkReader)
    disassembler = Disassembler(adapter, disasm)
    while True:
        chunk = chunkReader.nextWord()
        if chunk != None:
            disassembler.disasm(chunk)
        else:
            break
    disasm.close()

def main(argv):
    global DisasmFileSignature
    if len(argv) < 2:
        print("Disassembly usage python3 gen68krybaby.py genesisRom.bin")
        print(f"Assembly usage python3 gen68krybaby.py genesisRom.bin.{DisasmFileSignature}")
        exit(1)

    filePath = argv[1]

    if filePath.endswith(f".{DisasmFileSignature}") or filePath.endswith(f".{GenericAsmFileSignature}"):
        assembly(filePath)
    else:
        disassembly(filePath)

    exit(0)

main(sys.argv)
