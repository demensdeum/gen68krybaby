import os
import sys
import binascii
from enum import Enum

if len(sys.argv) < 2:
    print("Usage python3 gen68krybaby.py genesisRom.bin")
    exit(1)

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
    
    class State(Enum):
        Data = 1
        Commands = 2            
    
    def __init__(self, input, output):
        self.EntryPoint = 512
        
        self.subroutinesAdresses = {self.EntryPoint}
        self.segmentStartAddress = None
        self.lhsChunk = None
        self.rhsChunk = None
        self.state = self.State.Data
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
            self.output.write("ROM HEADER:\n")
        
        if chunk.address in self.subroutinesAdresses:
            self.state = self.State.Commands
            self.output.write(f"\nSUBROUTINE_{self.readableAddress(chunk.address)}:\n")
        
        if self.state == self.State.Commands:
            if self.lhsChunk == None:
                self.lhsChunk = chunk
            elif self.rhsChunk == None:
                self.rhsChunk = chunk
                output = self.disasmCommandChunks()
                self.output.write(f"\t\t{output}")

filePath = sys.argv[1]
disasmFilePath = f"{filePath}.disasm"
disasm = open(disasmFilePath, 'w')
chunkReader = ChunkReader(filePath)
adapter = DisassemblerToChunkReaderAdapter(chunkReader)
disassembler = Disassembler(adapter, disasm)

while True:
    chunk = chunkReader.nextChunk()
    if chunk != None:
        disassembledChunk = disassembler.disasm(chunk)
    else:
        break
    
disasm.close()

exit(0)
