unit uKcpDef;

interface
uses
  System.SysUtils, Winapi.Windows;

{$INCLUDE 'kcpdef.inc'}

type
{$ifdef IUNICODE}
  TChar     = WideChar;
  LPTChar   = PWideChar;
{$else}
  TChar     = AnsiChar;
  LPTChar   = PAnsiChar;
{$endif}
  TChar_t   = Array[0..$effffff] Of TChar;
  TChar_p   = ^TChar_t;

  LSTR      = PAnsiChar;
  LWSTR     = PWideChar;

  TSTR      = TChar;
  PTSTR     = LPTChar;

type
  Int8      = ShortInt;
  Int16     = SmallInt;
  Int32     = Integer;
  //Int64     = Int64;

  UInt8     = Byte;
  UInt16    = Word;
  UInt32    = Cardinal;
  //UInt64    = UInt64;

{$ifdef CPUX64}
  IntPtr    = NativeInt;
  UIntPtr   = NativeUInt;
{$else}
  IntPtr    = Int32;
  UIntPtr   = UInt32;
{$endif}

  PInt8     = ^Int8;
  PInt16    = ^Int16;
  PInt32    = ^Int32;
  PInt64    = ^Int64;

  PUInt8    = ^UInt8;
  PUInt16   = ^UInt16;
  PUInt32   = ^UInt32;
  PUInt64   = ^UInt64;

  Int8_t    = Array[0..$effffff] Of Int8;
  Int16_t   = Array[0..$effffff] Of Int16;
  Int32_t   = Array[0..$effffff] Of Int32;
  Int64_t   = Array[0..$ffffffe] Of Int64;

  UInt8_t   = Array[0..$effffff] Of UInt8;
  UInt16_t  = Array[0..$effffff] Of UInt16;
  UInt32_t  = Array[0..$effffff] Of UInt32;
  UInt64_t  = Array[0..$ffffffe] Of UInt64;

  Int8_p    = ^Int8_t;
  Int16_p   = ^Int16_t;
  Int32_p   = ^Int32_t;
  Int64_p   = ^Int64_t;

  UInt8_p   = ^UInt8_t;
  UInt16_p  = ^UInt16_t;
  UInt32_p  = ^UInt32_t;
  UInt64_p  = ^UInt64_t;

  PIntPtr   = ^IntPtr;
  PUIntPtr  = ^UIntPtr;
  IntPtr_t  = Array[0..$ffffffe] Of IntPtr;
  UIntPtr_t = Array[0..$ffffffe] Of UIntPtr;

  IntPtr_p  = ^IntPtr_t;
  UIntPtr_p = ^UIntPtr_t;

  SIZE_T    = UIntPtr;
  SIZE_P    = ^UIntPtr;

type
  Float4    = Single;
  PFloat4   = ^Float4;
  Float4_t  = Array[0..$effffff] Of Float4;
  Float4_p  = ^Float4_t;

  Float8    = Double;
  PFloat8   = ^Float8;
  Float8_t  = Array[0..$ffffffe] Of Float8;
  Float8_p  = ^Float8_t;

  { IKCPSEG }
  PKcpSeg = ^TKcpSeg;
  TKcpSeg = record
    // KCP SEGMENT QUEUE
    next:     PKcpSeg;
    prev:     PKcpSeg;
    // KCP SEGMENT QUEUE END
    conv:     UInt32;
    cmd:      UInt32;
    frg:      UInt32;
    wnd:      UInt32;
    ts:       UInt32;
    sn:       UInt32;
    una:      UInt32;
    len:      UInt32;
    resendts: UInt32;
    rto:      UInt32;
    fastack:  UInt32;
    xmit:     UInt32;
    data:     UInt8;
  end;

  { IKCPCB }
  PkcpCb = ^TKcpCb;
  // Function Define
  TOutPut   = function(const buf: PUInt8; len: Int32; kcp: PKcpCb; user: Pointer): Boolean;
  TWriteLog = procedure(const buf: PTSTR; kcp: PKcpCb; user: Pointer);
  TMalloc   = function(size: UInt32): Pointer;
  TFree     = procedure(buff: Pointer);
  TKcpCb = record
    conv, mtu,
    mss, state:             UInt32;
    snd_una, snd_nxt,
    rcv_nxt:                UInt32;
    ts_recent, ts_lastack,
    ssthresh:               UInt32;
    rx_rttval, rx_srtt,
    rx_rto, rx_minrto:      Int32;
    snd_wnd, rcv_wnd,
    rmt_wnd, cwnd, probe:   UInt32;
    current, interval,
    ts_flush, xmit:         UInt32;
    nrcv_buf, nsnd_buf:     UInt32;
    nrcv_que, nsnd_que:     UInt32;
    nodelay, updated:       UInt32;
    ts_probe, probe_wait:   UInt32;
    dead_link, incr:        UInt32;
    // Orign is TQueueHeade, Extract To TKcpSeg
    snd_queue:              TKcpSeg;
    rcv_queue:              TKcpSeg;
    snd_buf:                TKcpSeg;
    rcv_buf:                TKcpSeg;
    acklist:                PUInt32;
    ackcount, ackblock:     UInt32;
    user:                   Pointer;
    buffer:                 PUInt8;
    fastresend:             Int32;
    nocwnd, stream:         Int32;
    logmask:                Int32;
    output:                 TOutPut;
    writelog:               TWriteLog;
  end;

const
  CONST_IKCP_LOG_OUTPUT		  = 1;
  CONST_IKCP_LOG_INPUT		  = 2;
  CONST_IKCP_LOG_SEND		    = 4;
  CONST_IKCP_LOG_RECV		    = 8;
  CONST_IKCP_LOG_IN_DATA	  = 16;
  CONST_IKCP_LOG_IN_ACK		  = 32;
  CONST_IKCP_LOG_IN_PROBE	  = 64;
  CONST_IKCP_LOG_IN_WINS	  = 128;
  CONST_IKCP_LOG_OUT_DATA	  = 256;
  CONST_IKCP_LOG_OUT_ACK	  = 512;
  CONST_IKCP_LOG_OUT_PROBE	= 1024;
  CONST_IKCP_LOG_OUT_WINS	  = 2048;

procedure assert(f: Boolean; msg: string);
procedure printf(const fmt: PTSTR; const param: array of const);
procedure memcpy(d: Pointer; s: Pointer; len: Int32);

implementation

procedure assert(f: Boolean; msg: string);
begin
  if (f) then Exit;
  Writeln(msg);
  halt(0);
end;

procedure printf(const fmt: PTSTR; const param: array of const);
begin
  Write(Format(fmt, param));
end;

procedure memcpy(d: Pointer; s: Pointer; len: Int32);
begin
  CopyMemory(d, s, len);
end;

end.
