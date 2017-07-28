program Tester;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  Winapi.WinSock,
  Winapi.Windows,
  System.Generics.Collections,
  uKcp in 'uKcp.pas',
  uKcpDef in 'uKcpDef.pas';

type
  PTest = ^TTest;
  TTest = packed record
    a: Integer;
    b: array[0..100] of AnsiChar;
  end;

  // client udp
  TClientUDP = class
  private
    FSocket: TSocket;
    FAddr: TSockAddrIn;
    FLen: Integer;
    FKcp: PKcpCb;
    FCurrent: Integer;
    procedure InitKcp(mode: Integer; log: Boolean);
  public
    constructor Create(server: AnsiString; port: Word; mode: Integer; log: Boolean); overload;
    constructor Create(socket: TSocket; var addr: TSockAddrIn; len: Integer; mode: Integer; log: Boolean); overload;
    destructor Destroy();
    function send(const buf: PUInt8; len: Integer): Integer;
    function recv(const buf: PUInt8; len: Integer): Integer;
    procedure input(const buf: PUInt8; len: Integer);
    procedure tick();
    procedure processmsg();
  end;

  // server udp
  TServerUDP = class
  private
    FSocket: TSocket;
    FAddr: TSockAddrIn;
    FConnList: TDictionary<TSockAddrIn, TClientUDP>;
    FMode: Integer;
    FLog: Boolean;
  public
    procedure LoopMsg();
  public
    constructor Create(port: Word; mode: Integer; log: Boolean);
    destructor Destroy();
  end;

function iclock(): DWORD;
begin
  Result := GetTickCount();
end;

// 打印日志
procedure outmsg(const buf: PTSTR; kcp: PKcpCb; user: Pointer);
begin
  Write(buf);
end;

// 模拟网络：模拟发送一个 udp包
function udp_output(const buf: PUInt8; len: Integer; kcp: PkcpCb; user: Pointer): Integer;
var
  i: TClientUDP;
begin
  i := TClientUDP(user);
  Result := sendto(i.FSocket, buf^, len, 0, i.FAddr, i.FLen);
end;

{ TClientUDP }
constructor TClientUDP.Create(server: AnsiString; port: Word; mode: Integer;
  log: Boolean);
var
  time: TTimeVal;
begin
  FSocket := socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  time.tv_sec := 1;
  time.tv_usec := 0;
  setsockopt(FSocket, SOL_SOCKET, SO_RCVTIMEO, PAnsiChar(@time), SizeOf(time));
  FAddr.sin_family := AF_INET;
  FAddr.sin_port := htons(port);
  FAddr.sin_addr.S_addr := inet_addr(PAnsiChar(server));
  FLen := SizeOf(FAddr);
  FCurrent := 0;
  InitKcp(mode, log);
end;

constructor TClientUDP.Create(socket: TSocket; var addr: TSockAddrIn; len: Integer;
  mode: Integer; log: Boolean);
begin
  FSocket := socket;
  FAddr := addr;
  FLen := len;
  FCurrent := 0;
  InitKcp(mode, log);
end;

destructor TClientUDP.Destroy;
begin
  ikcp_release(FKcp);
  closesocket(FSocket);
end;

procedure TClientUDP.InitKcp(mode: Integer; log: Boolean);
begin
  FKcp := ikcp_create($11223344, Pointer(Self));
  ikcp_setoutput(FKcp, @udp_output);
  if (log) then
  begin
    @FKcp^.writelog := @outmsg;
    FKcp^.logmask := $7fffffff;
  end;
  ikcp_wndsize(FKcp, 128, 128);
  if (mode = 0) then
  begin
		// 默认模式
		ikcp_nodelay(FKcp, 0, 10, 0, 0);
  end
  else if (mode = 1) then
  begin
		// 普通模式，关闭流控等
		ikcp_nodelay(FKcp, 0, 10, 0, 1);
  end
  else begin
		// 启动快速模式
		// 第二个参数 nodelay-启用以后若干常规加速将启动
		// 第三个参数 interval为内部处理时钟，默认设置为 10ms
		// 第四个参数 resend为快速重传指标，设置为2
		// 第五个参数 为是否禁用常规流控，这里禁止
		ikcp_nodelay(FKcp, 1, 10, 2, 1);
		FKcp^.rx_minrto := 10;
		FKcp^.fastresend := 1;
  end;
  tick();
end;

procedure TClientUDP.input(const buf: PUInt8; len: Integer);
begin
  ikcp_input(FKcp, buf, len);
end;

procedure TClientUDP.processmsg;
var
  ret: Integer;
  buf: array[0..1024] of AnsiChar;
begin
  ret := recvfrom(FSocket, buf[0], SizeOf(buf), 0, FAddr, FLen);
  if (ret > 0) then
  begin
    input(@buf[0], ret);
  end;
end;

function TClientUDP.recv(const buf: PUInt8; len: Integer): Integer;
begin
  Result := ikcp_recv(FKcp, buf, len);
end;

function TClientUDP.send(const buf: PUInt8; len: Integer): Integer;
begin
  Result := ikcp_send(FKcp, buf, len);
end;

procedure TClientUDP.tick;
begin
  ikcp_update(FKcp, iclock());
end;

{ TServerUDP }
constructor TServerUDP.Create(port: Word; mode: Integer; log: Boolean);
var
  time: TTimeVal;
begin
  FSocket := socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  time.tv_sec := 1;
  time.tv_usec := 0;
  setsockopt(FSocket, SOL_SOCKET, SO_RCVTIMEO, PAnsiChar(@time), SizeOf(time));
  FAddr.sin_family := AF_INET;
  FAddr.sin_port := htons(port);
  FAddr.sin_addr.S_addr := htonl(INADDR_ANY);
  FMode := mode;
  FLog := log;
  bind(FSocket, FAddr, SizeOf(FAddr));
  FConnList := TDictionary<TSockAddrIn, TClientUDP>.Create();
end;

destructor TServerUDP.Destroy;
var
  i: TClientUDP;
begin
  closesocket(FSocket);
  for i in FConnList.Values do
  begin
    i.Free;
  end;
  FreeAndNil(FConnList);
end;

procedure TServerUDP.LoopMsg;
var
  ret, len: Integer;
  buf: array [0..1024] of AnsiChar;
  addr: TSockAddrIn;
  cli: TClientUDP;
  test: TTest;
begin
  // 循环处理连接
  while True do
  begin
    len := SizeOf(addr);
    ret := recvfrom(FSocket, buf[0], SizeOf(buf), 0, addr, len);
    if (ret > 0) then
    begin
      if (not FConnList.ContainsKey(addr)) then
      begin
        Writeln('create new client class');
        cli := TClientUDP.Create(FSocket, addr, len, FMode, FLog);
        FConnList.Add(addr, cli);
      end
      else
        cli := FConnList.Items[addr];
      cli.input(@buf[0], ret);
    end;
    for cli in FConnList.Values do
    begin
      ret := cli.recv(@test, SizeOf(test));
      if (ret > 0) then
      begin
        if (test.a <> cli.FCurrent) then
        begin
          MessageBox(0, 'error', nil, 0);
          Abort;
        end;
        Writeln(Format('index: %d, str: %s', [test.a, test.b]));
        Inc(cli.FCurrent);
      end;
      cli.tick();
    end;
    Sleep(10);
  end;
end;

var
  wsa: TWSAData;
  ser: TServerUDP;
  cli: TClientUDP;
  count: Integer;
  test: TTest;
  server: Boolean;
  mode: Integer;
  log: Boolean;
  address: string;
  port: Integer;

procedure Usage();
begin
  Writeln('usage:' + #13#10 + 'start server mode: <exe> -s <mode> <log> <port>' + #13#10 +
    'start client mode: <exe> -c <mode> <log> <server address> <port>');
  Writeln('mode: 0 = (default), 1 = (normal), 2 = (fast)');
  Writeln('log: 0 = (off), 1 = (on)');
end;

procedure PraseParam();
begin
  if (ParamCount <= 0) then
  begin
    Usage();
    Abort();
  end;
  if (ParamStr(1) = '-s') then
  begin
    mode := StrToInt(ParamStr(2));
    log := False;
    if (ParamStr(3) = '1') then log := True;
    port := StrToInt(ParamStr(4));
    server := True;
  end
  else if (ParamStr(1) = '-c') then
  begin
    mode := StrToInt(ParamStr(2));
    log := False;
    if (ParamStr(3) = '1') then log := True;
    address := ParamStr(4);
    port := StrToInt(ParamStr(5));
    server := False;
  end
  else
  begin
    Usage();
    Abort;
  end;
end;

begin
  try
    PraseParam();
    WSAStartup($0101, wsa);
    if (server) then
    begin
      Writeln('create server');
      ser := TServerUDP.Create(port, mode, log);
      ser.LoopMsg();
    end
    else begin
      Writeln('create client');
      cli := TClientUDP.Create(address, port, mode, log);
      count := 0;
      while True do
      begin
        test.a := count;
        wsprintfA(@test.b[0], 'kcp tester: (%d)', count);
        Inc(count);
        cli.send(@test, SizeOf(test));
        cli.tick();
        cli.processmsg();
        Sleep(100);
      end;
    end;
    WSACleanup();
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
