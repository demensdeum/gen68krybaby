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
        address = self.cursor / 2
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

    def fetchMemoryAddress(self):
        output = "0x"
        for i in range(4):
            output += self.chunkReader.nextChunk().data
        return output
            
class Disassembler:
    
    class State(Enum):
        Data = 1
        Commands = 2            
    
    def __init__(self, dataSource):
        self.EntryPoint = 512
        
        self.segmentStartAddress = None
        self.lhsChunk = None
        self.rhsChunk = None
        self.state = self.State.Data
        self.dataSource = dataSource
        
    def disasmCommandChunks(self):
        output = f"{self.lhsChunk.data}{self.rhsChunk.data}".upper()
        
        self.lhsChunk = None
        self.rhsChunk = None        
        
        output = output.replace("4EB9", "JSR")
        output = output.replace("4E71", "NOP")
        output = output.replace("4E75","RTS")
        
        if output == "JSR":
            memoryAddress = self.dataSource.fetchMemoryAddress()
            output = f"JSR {memoryAddress}\n"
            return output
        
        elif output == "NOP":
            output = "NOP\n"
            return output
        
        return f"{output}\n"
        
    def disasm(self, chunk):
        if self.segmentStartAddress == None:
            self.segmentStartAddress = chunk.address
            return f"ROM HEADER:\n"
        
        elif chunk.address == self.EntryPoint:
            self.segmentStartAddress = chunk.address
            self.state = self.State.Commands
            self.lhsChunk = chunk
            return f"\nRESET:\n"
        
        if self.state == self.State.Commands:
            if self.lhsChunk == None:
                self.lhsChunk = chunk
                return ""
            
            elif self.rhsChunk == None:
                self.rhsChunk = chunk
                return self.disasmCommandChunks()
        else:
            return ""

filePath = sys.argv[1]
disasmFilePath = f"{filePath}.disasm"
disasm = open(disasmFilePath, 'w')
chunkReader = ChunkReader(filePath)
disassemblerToChunkReaderAdapter = DisassemblerToChunkReaderAdapter(chunkReader)
disassembler = Disassembler(disassemblerToChunkReaderAdapter)

while True:
    chunk = chunkReader.nextChunk()
    if chunk != None:
        disassembledChunk = disassembler.disasm(chunk)
        disasm.write(disassembledChunk)
    else:
        break
    
disasm.close()

exit(0)
