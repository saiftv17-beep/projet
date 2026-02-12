# fadai
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad
from protobuf_decoder.protobuf_decoder import Parser
import asyncio, json

async def EncryptPacket(HexData, key=None, iv=None):
    DefaultKey = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    DefaultIv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    Key = key if key else DefaultKey
    Iv = iv if iv else DefaultIv
    cipher = AES.new(Key, AES.MODE_CBC, Iv)
    CipherText = cipher.encrypt(pad(bytes.fromhex(HexData), AES.block_size))
    return CipherText.hex()

async def DecodeHex(Hex):
    LenHeader = hex(Hex)
    FinalResult = str(LenHeader)[2:]
    if len(FinalResult) == 1:
        FinalResult = "0" + FinalResult
        return FinalResult
    else:
        return FinalResult

async def EncodeVarint(number):
    if number < 0:
        raise ValueError("Number must be non-negative")
    EncodedBytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        EncodedBytes.append(byte)
        if not number:
            break
    return bytes(EncodedBytes)

async def CreateVarintField(FieldNumber, Value):
    FieldHeader = (FieldNumber << 3) | 0
    HeaderBytes = await EncodeVarint(FieldHeader)
    ValueBytes = await EncodeVarint(Value)
    return HeaderBytes + ValueBytes

async def CreateLengthDelimitedField(FieldNumber, Value):
    FieldHeader = (FieldNumber << 3) | 2
    EncodedValue = Value.encode() if isinstance(Value, str) else Value
    HeaderBytes = await EncodeVarint(FieldHeader)
    LengthBytes = await EncodeVarint(len(EncodedValue))
    return HeaderBytes + LengthBytes + EncodedValue

async def CreateProtobufPacket(Fields):
    packet = bytearray()
    for FieldNumber, Value in Fields.items():
        if isinstance(Value, dict):
            NestedPacket = await CreateProtobufPacket(Value)
            FieldBytes = await CreateLengthDelimitedField(FieldNumber, NestedPacket)
            packet.extend(FieldBytes)
        elif isinstance(Value, int):
            FieldBytes = await CreateVarintField(FieldNumber, Value)
            packet.extend(FieldBytes)
        elif isinstance(Value, str) or isinstance(Value, bytes):
            FieldBytes = await CreateLengthDelimitedField(FieldNumber, Value)
            packet.extend(FieldBytes)
    return bytes(packet)
    
async def ParseResults(ParsedResults):
    ResultDict = {}
    for Result in ParsedResults:
        FieldData = {}
        FieldData['wire_type'] = Result.wire_type
        if Result.wire_type == "varint":
            FieldData['data'] = Result.data
            ResultDict[Result.field] = FieldData
        elif Result.wire_type == "string":
            FieldData['data'] = Result.data
            ResultDict[Result.field] = FieldData
        elif Result.wire_type == 'length_delimited':
            FieldData["data"] = await ParseResults(Result.data.results)
            ResultDict[Result.field] = FieldData
    return ResultDict
    
async def DecodeProtobufPacket(HexData):
    ParsedResults = Parser().parse(HexData)
    ParsedResultsDict = await ParseResults(ParsedResults)
    return json.dumps(ParsedResultsDict)
    
async def GlitchFixKick(PlayerId, key, iv):
    fields = {1: 35, 2: {1: int(PlayerId)}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)
    
async def LeaveTeam(BotUid, key, iv):
    fields = {1: 7, 2: {1: BotUid}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)
    
async def StartGame(BotUid, key, iv):
    fields = {1: 9, 2: {1: BotUid}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)
    
async def SwitchLoneWolfDule(BotUid, key, iv):
    fields = {1: 17, 2: {1: BotUid, 2: 1, 3: 1, 4: 43, 5: "\u000b", 8: 1, 19: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)
    
async def InvitePlayer(PlayerId, key, iv):
    fields = {1: 2, 2: {1: int(PlayerId), 2: "ME", 4: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)
    
async def PlayerStatus(PlayerId, key, iv):
    fields = {1: 1, 2: {1: int(PlayerId), 5: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0F19', key, iv)
    
async def SwitchLoneWolf(key, iv):
    fields = {1: 1, 2: {2: "\u000b", 3: 43, 4: 1, 5: "en", 9: 1, 10: "\u0001\t\n\u000b\u0012\u0019\u001a ", 11: 1, 13: 1, 14: {2: 86, 6: 11, 8: "1.118.10", 9: 3, 10: 1}}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)

async def GenPacket(Packet, H, key, iv):
    PacketEncrypt = await EncryptPacket(Packet , key , iv)
    HeaderLenthFinal = await DecodeHex(int(len(PacketEncrypt) // 2))
    if len(HeaderLenthFinal) == 2: Header = H + "000000"
    elif len(HeaderLenthFinal) == 3: Header = H + "00000"
    elif len(HeaderLenthFinal) == 4: Header = H + "0000"
    elif len(HeaderLenthFinal) == 5: Header = H + "000"
    else: print('Error => Generating The Packet !! ')
    return bytes.fromhex(Header + HeaderLenthFinal + PacketEncrypt)