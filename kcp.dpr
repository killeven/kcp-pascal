program kcp;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  Winapi.Windows,
  System.Generics.Collections,
  uKcp in 'uKcp.pas',
  uKcpDef in 'uKcpDef.pas';

var
  init: Boolean = false;
  start: UInt32;

function iclock(): UInt32;
begin
  if (not init) then
    start := GetTickCount();
  init := True;
  Result := GetTickCount() - start;
end;

procedure isleep(millisecond: UInt32);
begin
  Sleep(millisecond);
end;

type
  // 带延迟的数据包
  TDelayPacket = class
  private
    FPtr: PUInt8;
    FSize: Integer;
    FTs: UInt32;
  public
    property ptr: PUInt8 read FPtr;
    property size: Integer read FSize;
    property ts: UInt32 read FTs write FTs;
  public
    constructor Create(size: Integer; src: Pointer);
    destructor Destroy;
  end;
  // 均匀分布的随机数
  TRandom = class
  private
    FSize: Integer;
    FSeeds: TList<Integer>;
  public
    function MyRandom(): Integer;
  public
    constructor Create(size: Integer);
    destructor Destroy;
  end;
  // 网络延迟模拟器
  TLatencySimulator = class
  private
    FCurrent: UInt32;
    FLostRate: Integer;
    FRttmin: Integer;
    FRttmax: Integer;
    FNmax: Integer;
    FP12: TList<TDelayPacket>;
    FP21: TList<TDelayPacket>;
    FR12: TRandom;
    FR21: TRandom;
  public
    tx1: Int64;
    tx2: Int64;
  public
    // lostrate: 往返一周丢包率的百分比，默认 10%
    // rttmin：rtt最小值，默认 60
    // rttmax：rtt最大值，默认 125
    constructor Create(lostrate: Integer; rttmin: Integer; rttmax: Integer; nmax: Integer);
    destructor Destroy;
    procedure clear();
    procedure send(peer: Integer; data: Pointer; size: Integer);
    function recv(peer: Integer; data: Pointer; maxsize: Integer): Integer;
  end;

{ TDelayPacket }

constructor TDelayPacket.Create(size: Integer; src: Pointer);
begin
  FPtr := GetMemory(size);
  FSize := size;
  if (src <> nil) then CopyMemory(FPtr, src, size);
end;

destructor TDelayPacket.Destroy;
begin
  FreeMemory(FPtr);
end;

{ TRandom}
constructor TRandom.Create(size: Integer);
begin
  FSeeds := TList<Integer>.Create;
  FSeeds.Count := size;
  FSize := 0;
end;

function TRandom.MyRandom(): Integer;
var
  x, i: Integer;
begin
  if (FSeeds.Count = 0) then Exit(0);
  if (FSize = 0) then
  begin
    for i := 0 to FSeeds.Count - 1 do
    begin
      FSeeds[i] := i;
    end;
    FSize := FSeeds.Count;
  end;
  Randomize();
  i := Random(FSize);
  Result := FSeeds[i];
  Dec(FSize);
  FSeeds[i] := FSeeds[FSize];
end;

destructor TRandom.Destroy;
begin
  FreeAndNil(FSeeds);
end;


{ TLatencySimulator }

procedure TLatencySimulator.clear;
var
  t: TDelayPacket;
  i: Integer;
begin
  FreeAndNil(FR12);
  FreeAndNil(FR21);
  for i := 0 to FP12.Count - 1 do
  begin
    t := FP12[i];
    FreeAndNil(t);
  end;
    for i := 0 to FP21.Count - 1 do
  begin
    t := FP21[i];
    FreeAndNil(t);
  end;
  FreeAndNil(FP12);
  FreeAndNil(FP21);
end;

constructor TLatencySimulator.Create(lostrate, rttmin, rttmax, nmax: Integer);
begin
  FR12 := TRandom.Create(100);
  FR21 := TRandom.Create(100);
  FP12 := TList<TDelayPacket>.Create();
  FP21 := TList<TDelayPacket>.Create();
  FCurrent := iclock();
  FLostRate := lostrate div 2;
  FRttmin := rttmin div 2;
  FRttmax := rttmax div 2;
  FNmax := nmax;
  tx1 := 0;
  tx2 := 0;
end;

destructor TLatencySimulator.Destroy;
begin
  clear;
end;

function TLatencySimulator.recv(peer: Integer; data: Pointer;
  maxsize: Integer): Integer;
var
  pkt: TDelayPacket;
begin
  if (peer = 0) then
  begin
    if (FP21.Count = 0) then Exit(-1);
    pkt := FP21[0];
  end
  else
  begin
    if (FP12.Count = 0) then Exit(-1);
    pkt := FP12[0];
  end;
  FCurrent := iclock();
  if (FCurrent < pkt.ts) then Exit(-2);
  if (maxsize < pkt.size) then Exit(-3);
  if (peer = 0) then
    FP21.Remove(pkt)
  else
    FP12.Remove(pkt);
  maxsize := pkt.size;
  CopyMemory(data, pkt.ptr, maxsize);
  FreeAndNil(pkt);
  Result := maxsize;
end;

procedure TLatencySimulator.send(peer: Integer; data: Pointer; size: Integer);
var
  pkt: TDelayPacket;
  delay: UInt32;
begin
  if (peer = 0) then
  begin
    Inc(tx1);
    if (FR12.MyRandom() < FLostRate) then Exit;
    if (FP12.Count >= FNmax) then Exit;
  end
  else begin
    Inc(tx2);
    if (FR21.MyRandom() < FLostRate) then Exit;
    if (FP21.Count >= FNmax) then Exit;
  end;
  pkt := TDelayPacket.Create(size, data);
  FCurrent := iclock();
  delay := FRttmin;
  if (FRttmax > FRttmin) then
  begin
    Randomize();
    delay := delay + Random(FRttmax - FRttmin);
  end;
  pkt.ts := FCurrent + delay;
  if (peer = 0) then
    FP12.Add(pkt)
  else
    FP21.Add(pkt);
end;


var
  vnet: TLatencySimulator;
  id: Integer;

procedure outmsg(const buf: PTSTR; kcp: PKcpCb; user: Pointer);
begin
  Write(buf);
end;

// 模拟网络：模拟发送一个 udp包
function udp_output(const buf: PUInt8; len: Integer; kcp: PkcpCb; user: Pointer): Integer;
begin
  id := Integer(user);
  vnet.send(id, buf, len);
  Result := 0;
end;

type
  PTest = ^TTest;
  TTest = packed record
    a: Integer;
    b: Integer;
  end;

function getmode(i: integer): string;
begin
  case i of
    0: Result := 'default';
    1: Result := 'normal';
  else
    Result := 'fast';
  end;
end;

// 测试用例
procedure test(mode: Integer);
var
  kcp1, kcp2: PkcpCb;
  current, slap, index, next, ts1: UInt32;
  sumrtt: Int64;
  count, maxrtt, hr: Integer;
  buffer: array [0..2000] of AnsiChar;
  sn, ts, rtt: UInt32;
begin
  init := False;
  vnet := TLatencySimulator.Create(10, 60, 125, 1000);
  kcp1 := ikcp_create($11223344, Pointer(0));
  kcp2 := ikcp_create($11223344, Pointer(1));

  ikcp_setoutput(kcp1, @udp_output);
  ikcp_setoutput(kcp2, @udp_output);

  @kcp1^.writelog := @outmsg;
  @kcp2^.writelog := @outmsg;


  //kcp1^.logmask := $7FFFFFFF;
  //kcp2^.logmask := $7FFFFFFF;

  current := iclock();
  slap := current + 20;
  index := 0;
  next := 0;
  sumrtt := 0;
  count := 0;
  maxrtt := 0;

	// 配置窗口大小：平均延迟200ms，每20ms发送一个包，
	// 而考虑到丢包重发，设置最大收发窗口为128
	ikcp_wndsize(kcp1, 128, 128);
	ikcp_wndsize(kcp2, 128, 128);

  if (mode = 0) then
  begin
		// 默认模式
		ikcp_nodelay(kcp1, 0, 10, 0, 0);
		ikcp_nodelay(kcp2, 0, 10, 0, 0);
  end
  else if (mode = 1) then
  begin
		// 普通模式，关闭流控等
		ikcp_nodelay(kcp1, 0, 10, 0, 1);
		ikcp_nodelay(kcp2, 0, 10, 0, 1);
  end
  else begin
		// 启动快速模式
		// 第二个参数 nodelay-启用以后若干常规加速将启动
		// 第三个参数 interval为内部处理时钟，默认设置为 10ms
		// 第四个参数 resend为快速重传指标，设置为2
		// 第五个参数 为是否禁用常规流控，这里禁止
		ikcp_nodelay(kcp1, 1, 10, 2, 1);
		ikcp_nodelay(kcp2, 1, 10, 2, 1);
		kcp1^.rx_minrto := 10;
		kcp1^.fastresend := 1;
  end;

  ts1 := iclock();

  while True do
  begin
    isleep(1);
    current := iclock();
		ikcp_update(kcp1, iclock());
		ikcp_update(kcp2, iclock());
    // 每隔 20ms，kcp1发送数据
    while (current >= slap) do
    begin
      PTest(@buffer[0])^.a := index;
      PTest(@buffer[0])^.b := current;
      Inc(index);
      Inc(slap, 20);

      // 发送上层协议包
			ikcp_send(kcp1, @buffer[0], 8);
    end;

    // 处理虚拟网络：检测是否有udp包从p1->p2
    while True do
    begin
      hr := vnet.recv(1, @buffer[0], 2000);
      if (hr < 0) then Break;
			// 如果 p2收到udp，则作为下层协议输入到kcp2
			ikcp_input(kcp2, @buffer[0], hr);
    end;

    // 处理虚拟网络：检测是否有udp包从p2->p1
    while True do
    begin
      hr := vnet.recv(0, @buffer[0], 2000);
      if (hr < 0) then Break;
			// 如果 p1收到udp，则作为下层协议输入到kcp2
			ikcp_input(kcp1, @buffer[0], hr);
    end;

    // kcp2接收到任何包都返回回去
		while True do
    begin
			hr := ikcp_recv(kcp2, @buffer[0], 10);
			// 没有收到包就退出
			if (hr < 0) then break;
			// 如果收到包就回射
			ikcp_send(kcp2, @buffer[0], hr);
    end;

    // kcp1收到kcp2的回射数据
    while True do
    begin
      hr := ikcp_recv(kcp1, @buffer[0], 10);
      // 没有收到包就退出
			if (hr < 0) then break;
      sn := PTest(@buffer[0])^.a;
      ts := PTest(@buffer[0])^.b;
      rtt := current - ts;
      if (sn <> next) then
      begin
        // 如果收到的包不连续
        Writeln(Format('ERROR sn %d<->%d', [count, next]));
        Exit;
      end;

      Inc(next);
      Inc(sumrtt, rtt);
      Inc(count);
      if (rtt > maxrtt) then maxrtt := rtt;

      Writeln(Format('[RECV] mode=%s sn=%d rtt=%d', [getmode(mode), sn, rtt]));
    end;
    if (next > 1000) then Break;
  end;

  ts1 := iclock() - ts1;

  ikcp_release(kcp1);
  ikcp_release(kcp2);

  Writeln(Format('%s mode result (%dms)', [getmode(mode), ts1]));
  Writeln(Format('avgrtt=%d maxrtt=%d tx1=%d tx2=%d', [sumrtt mod count, maxrtt,
    vnet.tx1, vnet.tx2]));

  FreeAndNil(vnet);

  Writeln('press enter to next ...');
  readln;
end;

begin
try
  test(0);
  test(1);
  test(2);
except
  on E: Exception do
    Writeln(e.Message);
end;

end.
