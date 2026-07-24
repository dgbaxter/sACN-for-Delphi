//////project name
//sACN (E1.31)

//////description
//Utility library to talk sACN / Streaming ACN (ANSI E1.31), ie. DMX over ethernet
// modelled on DelphiArtNet.pas — focused on sending DMX levels

//////licence
//GNU Lesser General Public License (LGPL v3)

//////language/ide
//delphi

//////initial author
//Dave Baxter -> dave@baxeldata.com
// patterned after DelphiArtNet (Sebastian Oschatz / Dave Baxter)

unit DelphiSACN;

interface

uses
  Sysutils, Classes, Windows, Forms,
  IdGlobal, IdUDPServer, IdSocketHandle;

type

  { Full E1.31 data packet for 512 DMX slots (638 bytes).
    Multi-byte fields are stored in network byte order (big-endian). }
  TMSacnDmxPacket = packed record
    { --- ACN Root Layer (38 bytes) --- }
    PreambleSize   : array[0..1] of Byte;   // 0x0010
    PostambleSize  : array[0..1] of Byte;   // 0x0000
    ACNPacketID    : array[0..11] of AnsiChar; // 'ASC-E1.17'#0#0#0
    RootFlagsLen   : array[0..1] of Byte;   // 0x726e for full packet
    RootVector     : array[0..3] of Byte;   // VECTOR_ROOT_E131_DATA = 4
    CID            : array[0..15] of Byte;  // Component Identifier (UUID)

    { --- E1.31 Framing Layer (77 bytes) --- }
    FrameFlagsLen  : array[0..1] of Byte;   // 0x7258 for full packet
    FrameVector    : array[0..3] of Byte;   // VECTOR_E131_DATA_PACKET = 2
    SourceName     : array[0..63] of AnsiChar;
    Priority       : Byte;                  // 0..200, default 100
    SyncAddress    : array[0..1] of Byte;   // 0 = no sync
    Sequence       : Byte;
    Options        : Byte;                  // bit6 = StreamTerminated, bit7 = Preview
    Universe       : array[0..1] of Byte;   // 1..63999

    { --- DMP Layer (523 bytes) --- }
    DmpFlagsLen    : array[0..1] of Byte;   // 0x720b for full packet
    DmpVector      : Byte;                  // VECTOR_DMP_SET_PROPERTY = 2
    AddrDataType   : Byte;                  // 0xa1
    FirstAddress   : array[0..1] of Byte;   // 0x0000
    AddrIncrement  : array[0..1] of Byte;   // 0x0001
    PropValCount   : array[0..1] of Byte;   // 513 (start code + 512)
    StartCode      : Byte;                  // 0x00 = DMX512
    Data           : array[0..511] of Byte;
  end;

  TMSacnDecoder = class
  private
    FSocket: TIdUDPServer;
    FSequence: Byte;
    FCID: TGUID;
    FSourceName: AnsiString;
    FPriority: Byte;
    FPreviewData: Boolean;
    class procedure ReadCB(AThread: TIdUDPListenerThread; const AData: TIdBytes; ABinding: TIdSocketHandle);
    procedure PutUInt16BE(var Dest: array of Byte; Value: Word);
    procedure PutUInt32BE(var Dest: array of Byte; Value: LongWord);
    procedure ApplySourceName(var Packet: TMSacnDmxPacket);
  protected
    function CreateSACNDMX(Universe: Word; dmx: PByteArray; Options: Byte): TMSacnDmxPacket;
  public
    constructor Create;
    destructor Destroy; override;

    { DestAdr empty => multicast for Universe (239.255.hi.lo).
      DestAdr set  => unicast / explicit destination. }
    procedure SendSACNDMX(DestAdr: String; Universe: Word; dmx: PByteArray);

    { Send a final packet with the Stream Terminated option set. }
    procedure SendSACNTerminate(DestAdr: String; Universe: Word; dmx: PByteArray);

    { E1.31 multicast address for a universe number. }
    class function UniverseToMulticast(Universe: Word): String;

    property SourceName: AnsiString read FSourceName write FSourceName;
    property Priority: Byte read FPriority write FPriority;
    property PreviewData: Boolean read FPreviewData write FPreviewData;
    property CID: TGUID read FCID;
  end;

const
  cSACN_ACN_ID           = 'ASC-E1.17' + #0#0#0;
  cSACN_VECTOR_ROOT_DATA = $00000004;
  cSACN_VECTOR_DATA_PKT  = $00000002;
  cSACN_VECTOR_DMP_SET   = $02;
  cSACN_DMP_TYPE         = $a1;
  cSACN_OPT_TERMINATED   = $40;  // bit 6
  cSACN_OPT_PREVIEW      = $80;  // bit 7
  cSACN_DEFAULT_PRIORITY = 100;
  cSACN_PACKET_SIZE      = 638;

var
  GSACNPort: SmallInt = 5568;

implementation

uses
  IdUDPBase;

{--- big-endian helpers -------------------------------------------------------}

procedure TMSacnDecoder.PutUInt16BE(var Dest: array of Byte; Value: Word);
begin
  Dest[0] := Byte(Value shr 8);
  Dest[1] := Byte(Value and $FF);
end;

procedure TMSacnDecoder.PutUInt32BE(var Dest: array of Byte; Value: LongWord);
begin
  Dest[0] := Byte(Value shr 24);
  Dest[1] := Byte(Value shr 16);
  Dest[2] := Byte(Value shr 8);
  Dest[3] := Byte(Value and $FF);
end;

procedure TMSacnDecoder.ApplySourceName(var Packet: TMSacnDmxPacket);
var
  S: AnsiString;
  N, I: Integer;
begin
  FillChar(Packet.SourceName, SizeOf(Packet.SourceName), 0);
  S := FSourceName;
  N := Length(S);
  if N > 63 then
    N := 63;  // leave room for null terminator
  for I := 1 to N do
    Packet.SourceName[I - 1] := S[I];
end;

class function TMSacnDecoder.UniverseToMulticast(Universe: Word): String;
begin
  { E1.31: 239.255.<universe hi>.<universe lo> }
  Result := Format('239.255.%d.%d', [Hi(Universe), Lo(Universe)]);
end;

function TMSacnDecoder.CreateSACNDMX(Universe: Word; dmx: PByteArray; Options: Byte): TMSacnDmxPacket;
begin
  FillChar(Result, SizeOf(Result), 0);

  { Root Layer }
  PutUInt16BE(Result.PreambleSize, $0010);
  PutUInt16BE(Result.PostambleSize, $0000);
  Move(cSACN_ACN_ID[1], Result.ACNPacketID[0], 12);
  { Flags=0x7, Length from octet 16 through end = 622 (0x26E) }
  PutUInt16BE(Result.RootFlagsLen, $7000 or $026E);
  PutUInt32BE(Result.RootVector, cSACN_VECTOR_ROOT_DATA);
  Move(FCID, Result.CID[0], 16);

  { Framing Layer }
  { Flags=0x7, Length from octet 38 through end = 600 (0x258) }
  PutUInt16BE(Result.FrameFlagsLen, $7000 or $0258);
  PutUInt32BE(Result.FrameVector, cSACN_VECTOR_DATA_PKT);
  ApplySourceName(Result);
  Result.Priority := FPriority;
  PutUInt16BE(Result.SyncAddress, 0);
  Result.Sequence := FSequence;
  Inc(FSequence);  // wrap 255 -> 0 is fine per E1.31
  Result.Options := Options;
  if FPreviewData then
    Result.Options := Result.Options or cSACN_OPT_PREVIEW;
  PutUInt16BE(Result.Universe, Universe);

  { DMP Layer }
  { Flags=0x7, Length from octet 115 through end = 523 (0x20B) }
  PutUInt16BE(Result.DmpFlagsLen, $7000 or $020B);
  Result.DmpVector := cSACN_VECTOR_DMP_SET;
  Result.AddrDataType := cSACN_DMP_TYPE;
  PutUInt16BE(Result.FirstAddress, $0000);
  PutUInt16BE(Result.AddrIncrement, $0001);
  PutUInt16BE(Result.PropValCount, 513);  // start code + 512 slots
  Result.StartCode := $00;
  if dmx <> nil then
    CopyMemory(@Result.Data[0], @dmx[0], Length(Result.Data));
end;

procedure TMSacnDecoder.SendSACNDMX(DestAdr: String; Universe: Word; dmx: PByteArray);
var
  Packet: TMSacnDmxPacket;
  Buffer: TIdBytes;
  Dest: String;
begin
  try
    if Trim(DestAdr) = '' then
      Dest := UniverseToMulticast(Universe)
    else
      Dest := DestAdr;

    Packet := CreateSACNDMX(Universe, dmx, 0);
    Buffer := IdGlobal.RawToBytes(Packet, SizeOf(Packet));
    FSocket.SendBuffer(Dest, GSACNPort, Id_IPv4, Buffer);
  except
  end;
end;

procedure TMSacnDecoder.SendSACNTerminate(DestAdr: String; Universe: Word; dmx: PByteArray);
var
  Packet: TMSacnDmxPacket;
  Buffer: TIdBytes;
  Dest: String;
  Levels: array[0..511] of Byte;
begin
  try
    if Trim(DestAdr) = '' then
      Dest := UniverseToMulticast(Universe)
    else
      Dest := DestAdr;

    if dmx = nil then
    begin
      FillChar(Levels, SizeOf(Levels), 0);
      dmx := @Levels;
    end;

    Packet := CreateSACNDMX(Universe, dmx, cSACN_OPT_TERMINATED);
    Buffer := IdGlobal.RawToBytes(Packet, SizeOf(Packet));
    FSocket.SendBuffer(Dest, GSACNPort, Id_IPv4, Buffer);
  except
  end;
end;

constructor TMSacnDecoder.Create;
begin
  FSequence := 0;
  FPriority := cSACN_DEFAULT_PRIORITY;
  FSourceName := 'Cue Player One';
  FPreviewData := False;
  CreateGUID(FCID);

  try
    FSocket := TIdUDPServer.Create(nil);
    FSocket.ThreadedEvent := False;
    FSocket.DefaultPort := GSACNPort;
    FSocket.BroadcastEnabled := True;
    FSocket.OnUDPRead := ReadCB;
    FSocket.Active := True;
  except
    with Application do
    begin
      NormalizeTopMosts;
      MessageBox('The sACN port is already in use. You''ll need to change it.',
        'Could not start sACN', MB_ICONERROR or MB_OK);
      RestoreTopMosts;
    end;
  end;
end;

destructor TMSacnDecoder.Destroy;
begin
  if Assigned(FSocket) then
  begin
    FSocket.Active := False;
    FSocket.Free;
  end;
  inherited;
end;

class procedure TMSacnDecoder.ReadCB(AThread: TIdUDPListenerThread;
  const AData: TIdBytes; ABinding: TIdSocketHandle);
begin
  { Send-focused module — receive path reserved for future discovery / sync. }
end;

end.
