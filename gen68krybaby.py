import os
import sys
import binascii
from enum import Enum

DisasmFileSignature = "gen68KryBabyDisasm"
AsmFileSignature = "gen68KryBabyAsm.bin"
RomHeaderLabel = "ROM HEADER"

class State(Enum):
    Data = 1
    Commands = 2   

class Chunk:
    def __init__(self, data, address):
        self.data = data
        self.address = address

class ChunkReader:
    def __init__(self, filepath):
        rom = open(filepath, 'rb')
        content = rom.read()
        rom.close()
        self.hexString = str(binascii.hexlify(content))[2:-1]
        self.cursor = -1
        
    def nextChunk(self):
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
        return Chunk(data, address)

class DisassemblerToChunkReaderAdapter:
    def __init__(self, chunkReader):
        self.chunkReader = chunkReader

    def fetchLongWordMemoryAddress(self):
        output = "0x"
        for i in range(4):
            output += self.chunkReader.nextChunk().data
        return output
            
class Disassembler:         
    def __init__(self, input, output):
        self.EntryPoint = int(0x200)
        
        self.subroutinesAdresses = {self.EntryPoint}
        self.segmentStartAddress = None
        self.lhsChunk = None
        self.rhsChunk = None
        self.state = State.Data
        self.input = input
        self.output = output
        
    def readableAddress(self, address):
        padding = 10
        output = f"{address:#0{padding}x}"
        return output
    
    def addSubroutineAddress(self, address):
        self.subroutinesAdresses.add(int(address, base=16))
        
    def disasmCommandChunks(self):
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
            output = f"JSR {address}\n"
            return output

        elif output == "MOVEA.L,A0":
            address = self.input.fetchLongWordMemoryAddress()
            self.addSubroutineAddress(address)
            output = f"MOVEA.L {address},A0\n"
            return output

        elif output == "MOVEA.L,A1":
            address = self.input.fetchLongWordMemoryAddress()
            self.addSubroutineAddress(address)
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
            self.state = State.Commands
            self.output.write(f"\nSUBROUTINE_{self.readableAddress(chunk.address)}:\n")
        
        if self.state == State.Commands:
            if self.lhsChunk == None:
                self.lhsChunk = chunk
                
            elif self.rhsChunk == None:
                self.rhsChunk = chunk
                output = self.disasmCommandChunks()
                self.output.write(f"\t\t{output}")
        else:
            self.output.write(f" {chunk.data}")

class Assembler:
    def __init__(self, input, output):
        self.input = input
        self.output = output
        self.state = State.Data
        
    def chunkToHex(self, chunk):
        hexString = f"0x{chunk}"
        outputInt = int(hexString, 16)
        outputBytes = bytes([outputInt])
        self.output.write(outputBytes)        
        
    def commandToHex(self, commandLine):
        components = commandLine.split(" ")
        if len(components) < 1:
            return
        
        command = components[0]
        if command == "RTS":
            self.toHex("4E75")
            
        elif command == "NOP":
            self.toHex("4E71")
            
        elif command == "RTE":
            self.toHex("4E73")
            
        elif command == "JSR":
            if len(components) != 2:
                print(f"Incorrect JSR command count ({len(components)}): {commandLine}; len: {len(commandLine)}; waaa! waa!!")
                exit(1)
            else:
                address = components[1]
                self.jsrToHex(address)
                
        elif command == "MOVEA.L":
            if len(components) != 2:
                print(f"Incorrect JSR command count ({len(components)}): {commandLine}; len: {len(commandLine)}; waaa! waa!!")
                exit(1)
            else:
                arguments = components[1]
                if len(arguments) != 13:
                    print(f"Incorrect MOVEA.L command arguments ({len(arguments)}) != 13: {arguments}; waaa! waa!!")
                    exit(1)
                else:
                    address = arguments[2:10]
                    register = arguments[11:]
                    self.moveaToHex(address, register)
            
        else:
            print(f"Unknown command: {commandLine}; len: {len(commandLine)}; waa! waa!!!")
            exit(1)
        
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
        if len(address) != 10:
            print(f"Incorrect JSR command address len ({len(address)}) != 10: {address} waaa! waa!!")
            exit(1)
        address = address[2:]
        self.toHex("4EB9")
        self.addressToHex(address)
        
    def toHex(self, line):
        if len(line) == 4:
            self.toHex(line[:2])
            self.toHex(line[2:])
        elif len(line) == 2:
            chunk = line
            self.chunkToHex(chunk)
        else:
            self.commandToHex(line)
        
    def assembly(self, line):
        if line == f"{RomHeaderLabel}:\n":
            self.state = State.Data
            return
        elif line.startswith("SUBROUTINE_"):
            self.state = State.Commands
            return
        elif len(line.strip()) < 1:
            return
        
        line = line.strip()
        
        if self.state == State.Data:
            chunks = line.split(" ")
            for chunk in chunks:
                if len(chunk) == 2:
                    hexString = f"0x{chunk}"
                    outputInt = int(hexString, 16)
                    outputBytes = bytes([outputInt])
                    self.output.write(outputBytes)
        elif self.state == State.Commands:
            self.toHex(line)

def assembly(filePath):
    global AsmFileSignature
    disasm = open(filePath, "r")
    asmFilePath = f"{filePath}.{AsmFileSignature}"
    asm = open(asmFilePath, "wb")
    assembler = Assembler(None, asm)
    for line in disasm:
        assembler.assembly(line)    
    disasm.close()
    asm.close()

def disassembly(filePath):
    global DisasmFileSignature
    disasmFilePath = f"{filePath}.{DisasmFileSignature}"
    disasm = open(disasmFilePath, 'w')
    chunkReader = ChunkReader(filePath)
    adapter = DisassemblerToChunkReaderAdapter(chunkReader)
    disassembler = Disassembler(adapter, disasm)
    while True:
        chunk = chunkReader.nextChunk()
        if chunk != None:
            disassembler.disasm(chunk)
        else:
            break
    disasm.close()
    
def main(argv):
    if len(argv) < 2:
        print("Disassembly usage python3 gen68krybaby.py genesisRom.bin")
        print("Assembly usage python3 gen68krybaby.py genesisRom.bin.disasm")
        exit(1)
        
    filePath = argv[1]
    
    if filePath.endswith(f".{DisasmFileSignature}"):
        assembly(filePath)
    else:
        disassembly(filePath)
    
    exit(0)    

main(sys.argv)