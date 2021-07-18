import os
import sys
import binascii
from enum import Enum

GenericAsmFileSignature = "asm"
DisasmFileSignature = "gen68KryBabyDisasm"
AsmFileSignature = "gen68KryBabyAsm.bin"
RomHeaderLabel = "ROM HEADER"
SubroutineSignature = "SUBROUTINE_"
SubroutineWithAddressSignature = f"{SubroutineSignature}0x"
SubroutineWithAddressSignatureLength = len(SubroutineWithAddressSignature)
SubroutineWithAddressSignatureExample = f"{SubroutineSignature}0x00000000"
SubroutineWithAddressSignatureExampleLength = len(SubroutineWithAddressSignatureExample)

OpcodesHex = {
    "MOVE.B" : "1029",
    "ANDI.B" : "0200",
    "JSR"    : "4EB9",
    "NOP"    : "4E71",
    "RTS"    : "4E75",
    "RTE"    : "4E73",
    "RTR"    : "4E77",
    "MOVE.B" : "1029",
    "MOVEA.L,A0" : "2079",
    "MOVEA.L,A1" : "2279",
    "MOVE.L" : "237C"
}

HexToOpcodes = {value: key for key, value in OpcodesHex.items()}

def Kry(message, exitCode = 1):
    print(message)
    exit(1)

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
    
    def fetchLongWord(self):
        output = ""
        for i in range(4):
            output += self.wordsReader.nextWord().data
        return output
    
    def fetchWord(self):
        output = ""
        for i in range(2):
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

    def resolveRegistry(self, registry):
        registry = registry.upper()
        if registry == "2F00":
            return "A1"
        else:
            return registry
        
    def resolveLongWord(self, longWord):
        if longWord == "53454741":
            return "\"SEGA\""
        else:
            return longWord

    def disasmOperationWords(self):
        output = f"{self.lhsChunk.data}{self.rhsChunk.data}".upper()

        self.lhsChunk = None
        self.rhsChunk = None

        for opcode, hex in OpcodesHex.items():
            output = output.replace(hex, opcode)

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
        
        elif output == "MOVE.B":
            arguments = self.input.fetchWord()
            source = arguments[2:].upper()
            output += " "
            if source == "01":
                output += "A1"
            else:
                output += f"0x{source}"
            output += ","
            destination = arguments[:2]
            if destination == "EF":
                output += "D0"
            else:
                output += f"0x{destination}"
            output += "\n"
            return output
        
        elif output == "ANDI.B":
            arguments = self.input.fetchWord()
            output += " "
            data = arguments[2:].upper()    
            output += f"0x{data}"
            output += ","
            destination = arguments[:2]
            if destination == "00":
                output += "D0"
            else:
                output += f"0x{destination}"
            output += "\n"
            return output        
        
        elif output == "MOVE.L":
            ascii = self.resolveLongWord(self.input.fetchLongWord())
            address = self.resolveRegistry(self.input.fetchWord())
            output = f"MOVE.L {ascii},{address}"

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
        self.subroutines = dict()

    def andibToHex(self, data, destination):
        if len(data) != 4:
            Kry(f"Wrong ANBI data length must be 4!!! {data}!! waaahaa!!")
        data = data[2:]
        if destination == "D0":
           destination = "00"
        elif len(destination) == 4 and destination.startswith("0x"):
            destination = destination[2:]
        else:
            Kry("Unknown destination format for ANDI.B!! {destination}")
        self.toHex(OpcodesHex["ANDI.B"])
        self.toHex(destination)
        self.toHex(data)

    def writeWordToHex(self, word):
        if len(word) != 2:
            Kry(f"Word to hex length must be 2!! word {word} len {len(word)}!! waa!!!!")
        hexString = f"0x{word}"
        outputInt = int(hexString, 16)
        outputBytes = bytes([outputInt])
        self.output.write(outputBytes)

    def movebToHex(self, source, destination):        
        if source == "A1":
            source = "0x01"
            
        if len(source) == 4 and source.startswith("0x"):
            source = source[2:]
        else:
            Kry(f"waaa!! Incorrect MOVE.B source!! {source}")
            
        if destination == "D0":
            destination = "0xEF"
            
        if len(destination) == 4 and destination.startswith("0x"):
            destination = destination[2:]
        else:
            Kry(f"waaa!! Incorrect MOVE.B destination!! {destination}")
            
        self.toHex(OpcodesHex["MOVE.B"])            
        self.toHex(destination)
        self.toHex(source)        

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
            
        elif operation == "ANDI.B":
            if len(components) != 2:
                Kry(f"Incorrect ANDI.B operation count: ({len(components)}): {operationLine}; Must be 2")
            arguments = components[1].split(",")
            if len(arguments) != 2:
                Kry(f"Incorrect ANDI.B operation arguments: ({len(arguments)}): {arguments}; Must be 2")            
            data = arguments[0]
            destination = arguments[1]
            self.andibToHex(data, destination)
            
        elif operation == "MOVE.B":
            if len(components) != 2:
                Kry(f"Incorrect MOVE.B operaion count: ({len(components)}): {operationLine}; Must be 2")
            arguments = components[1].split(",")
            if len(arguments) != 2:
                Kry(f"Incorrect MOVE.B operation arguments: ({len(arguments)}): {arguments}; Must be 2")
            source = arguments[0]
            destination = arguments[1]
            self.movebToHex(source, destination)

        elif operation == "JSR":
            if len(components) != 2:
                Kry(f"Incorrect JSR operation count ({len(components)}): {operationLine}; len: {len(operationLine)}; waaa! waa!!")
            else:
                address = components[1]
                self.jsrToHex(address)

        elif operation == "MOVE.L":
            if len(components) != 2:
                Kry(f"Incorrect MOVE.L operation count ({len(components)}): {operationLine}; len: {len(operationLine)}; waaa! waa!!")
                
            arguments = components[1]
            if len(arguments) == 9:
                longWord = arguments[1:5]
                registry = arguments[7:9]
                self.movlToHex(longWord, registry)                
            elif len(arguments) == 13:
                longWord = arguments[:8]
                registry = arguments[9:]
                self.movlToHex(longWord, registry)
            else:
                Kry("Incorrect MOV.L length!! operationLine: {operationLine} !! waaa!!!")

        elif operation == "MOVEA.L":
            if len(components) != 2:
                Kry(f"Incorrect JSR operation count ({len(components)}): {operationLine}; len: {len(operationLine)}; waaa! waa!!")
            else:
                arguments = components[1]
                if len(arguments) != 13:
                    Kry(f"Incorrect MOVEA.L operation arguments ({len(arguments)}) != 13: {arguments}; waaa! waa!!")
                else:
                    address = arguments[2:10]
                    register = arguments[11:]
                    self.moveaToHex(address, register)

        else:
            Kry(f"Unknown operation: {operationLine}; len: {len(operationLine)}; waa! waa!!!")

    def cursor(self):
        return self.output.tell()

    def addressToHex(self, address):
        self.toHex(address[0:4])
        self.toHex(address[4:8])

    def longWordAsciiAsHex(self, asciiLongWord):
        output = ""
        for char in asciiLongWord:
            hexCode = hex(ord(char))[2:]
            output += hexCode
        return output

    def movlToHex(self, longWord, registry):
        self.toHex("237C")
        if len(longWord) == 4:
            self.toHex(self.longWordAsciiAsHex(longWord))
        elif len(longWord) == 8:
            self.toHex(longWord)
        else:
            Kry(f"longWord:{longWord} length is incorrect for movl!! waa")
            
        if registry == "A1":
            self.toHex("2F00")
        elif len(registry) == 4:
            self.toHex(registry)

    def moveaToHex(self, address, register):
        if register == "A0":
            self.toHex("2079")
        elif register == "A1":
            self.toHex("2279")
        self.addressToHex(address)

    def jsrToHex(self, address):
        self.toHex("4EB9")
        if address.startswith(SubroutineWithAddressSignature) and len(address) == SubroutineWithAddressSignatureExampleLength:
            hexAddress = address[SubroutineWithAddressSignatureLength:]
            self.addressToHex(hexAddress)
        elif address.startswith(SubroutineSignature):
            self.subroutinesPointers.append(self.Subroutine(address, self.cursor()))
            hexAddress = HexAddress(len(self.subroutinesPointers) - 1)[2:]
            self.addressToHex(hexAddress)
        else:
            Kry(f"Incorrect JSR operation address, must start with {SubroutineSignature} or as hex address (0x00000200 for example); current address: {address}; waa!!")

    def toHex(self, line):
        if len(line) == 8:
            self.toHex(line[:4])
            self.toHex(line[4:])            
        elif len(line) == 4:
            self.toHex(line[:2])
            self.toHex(line[2:])
        elif len(line) == 2:
            word = line
            self.writeWordToHex(word)
        else:
            self.operationToHex(line)

    def assembly(self, line):
        if line == f"{RomHeaderLabel}:\n":
            self.state = State.Data
            return
        elif line.startswith(SubroutineSignature):
            self.state = State.Operations
            label = line.strip()[:-1]
            self.subroutines[label] = self.Subroutine(label, self.cursor())
            return
        elif len(line.strip()) < 1:
            return

        line = line.strip()
        line = line.split(";")
        if len(line) > 2:
            Kry(f"line: {line} is incorrect, len({len(line)}) > 2, must be less 2; waaa!!!!")
        if len(line) < 1:
            Kry(f"line: {line} is incorrect, len({len(line)}) < 1, must be more than 0; waaa!!")
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
            if pointer.label not in self.subroutines:
                Kry(f"Cannot resolve subroutine: {pointer.label}!! waaa!!!!")
            subroutine = self.subroutines[pointer.label]
            hexAddress = HexAddress(subroutine.address)[2:]
            self.addressToHex(hexAddress)

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
