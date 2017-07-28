//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
// Delphi Code By Killeven (at) f1u3t@qq.com
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//=====================================================================

{.$DEFINE QPRINT}
unit uKcp;

interface
uses
  uKcpDef, System.SysUtils;

{$INCLUDE 'kcpdef.inc'}

//---------------------------------------------------------------------
// interface
//---------------------------------------------------------------------

// create a new kcp control object, 'conv' must equal in two endpoint
// from the same connection. 'user' will be passed to the output callback
// output callback can be setup like this: 'kcp->output = my_udp_output'
function ikcp_create(conv: UInt32; user: Pointer): PKcpCb;

// release kcp control object
procedure ikcp_release(kcp: PkcpCb);

// set output callback, which will be invoked by kcp
procedure ikcp_setoutput(kcp: PkcpCb; output: TOutPut);

// user/upper level recv: returns size, returns below zero for EAGAIN
function ikcp_recv(kcp: PkcpCb; buffer: PUInt8; len: Int32): Int32;

// user/upper level send, returns below zero for error
function ikcp_send(kcp: PkcpCb; const buf: PUInt8; len: Int32): Int32;

// update state (call it repeatedly, every 10ms-100ms), or you can ask
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec.
procedure ikcp_update(kcp: PkcpCb; current: UInt32);

// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to
// schedule ikcp_update (eg. implementing an epoll-like mechanism,
// or optimize ikcp_update when handling massive kcp connections)
function ikcp_check(const kcp: PkcpCb; current: UInt32): UInt32;

// when you received a low level packet (eg. UDP packet), call it
function ikcp_input(kcp: PKcpCb; const buf: PUInt8; size: UInt32): Int32;

// flush pending data
procedure ikcp_flush(kcp: PkcpCb);

// check the size of next message in the recv queue
function ikcp_peeksize(const kcp: PkcpCb): Int32;

// change MTU size, default is 1400
function ikcp_setmtu(kcp: PKcpCb; mtu: Int32): Int32;

// set maximum window size: sndwnd=32, rcvwnd=32 by default
function ikcp_wndsize(kcp: PkcpCb; sndwnd: Int32; rcvwnd: Int32): Int32;

// get how many packet is waiting to be sent
function ikcp_waitsnd(const kcp: PKcpCb): Int32;

// fastest: ikcp_nodelay(kcp, 1, 20, 2, 1)
// nodelay: 0:disable(default), 1:enable
// interval: internal update timer interval in millisec, default is 100ms
// resend: 0:disable fast resend(default), 1:enable fast resend
// nc: 0:normal congestion control(default), 1:disable congestion control
function ikcp_nodelay(kcp: PkcpCb; nodelay: Int32; interval: Int32; resend: Int32; nc: Int32): Int32;

// read conv
function ikcp_getconv(const ptr: Pointer): UInt32;

// setup allocator
procedure ikcp_allocator(malloc: TMalloc; free: TFree);
procedure ikcp_log(kcp: PKcpCb; mask: Int32; const fmt: PTSTR; const param: array of const);

implementation

//=====================================================================
// KCP BASIC
//=====================================================================
const
  IKCP_RTO_NDL     = 30;		// no delay min rto
  IKCP_RTO_MIN     = 100;		// normal min rto
  IKCP_RTO_DEF     = 200;
  IKCP_RTO_MAX     = 60000;
  IKCP_CMD_PUSH    = 81;		// cmd: push data
  IKCP_CMD_ACK     = 82;		// cmd: ack
  IKCP_CMD_WASK    = 83;		// cmd: window probe (ask)
  IKCP_CMD_WINS    = 84;		// cmd: window size (tell)
  IKCP_ASK_SEND    = 1;		  // need to send IKCP_CMD_WASK
  IKCP_ASK_TELL    = 2;		  // need to send IKCP_CMD_WINS
  IKCP_WND_SND     = 32;
  IKCP_WND_RCV     = 32;
  IKCP_MTU_DEF     = 1400;
  IKCP_ACK_FAST	   = 3;
  IKCP_INTERVAL_   = 100;
  IKCP_OVERHEAD    = 24;
  IKCP_DEADLINK    = 20;
  IKCP_THRESH_INIT = 2;
  IKCP_THRESH_MIN  = 2;
  IKCP_PROBE_INIT  = 7000;		// 7 secs to probe window size
  IKCP_PROBE_LIMIT = 120000;	// up to 120 secs to probe window

// queue operation
procedure iqueue_init(p: PKcpSeg);
begin
  p^.next := p;
  p^.prev := p;
end;

function iqueue_is_empty(p: PKcpSeg): Boolean;
begin
  Result := (p = p^.next);
end;

procedure iqueue_add(node: PKcpSeg; head: PKcpSeg);
begin
  node^.prev := head;
  node^.next := head^.next;
  head^.next^.prev := node;
  head^.next := node;
end;

procedure iqueue_add_tail(node: PKcpSeg; head: PKcpSeg);
begin
  node^.prev := head^.prev;
  node^.next := head;
  head^.prev^.next := node;
  head^.prev := node;
end;

procedure iqueue_del(p: PKcpSeg);
begin
  p^.next^.prev := p^.prev;
  p^.prev^.next := p^.next;
  p^.next := nil;
  p^.prev := nil;
end;

procedure iqueue_del_init(p: PKcpSeg);
begin
  iqueue_del(p);
  iqueue_init(p);
end;

function iqueue_entry(seg: PKcpSeg): PKcpSeg;
begin
  Result := seg;
end;

//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------

// encode 8 bits unsigned int
function ikcp_encode8u(p: PUInt8; c: UInt8): PUInt8;
begin
  p^ := c;
  Result := PUInt8(UInt32(p) + 1);
end;

// decode 8 bits unsigned int
function ikcp_decode8u(p: PUInt8; c: PUInt8): PUInt8;
begin
  c^ := p^;
  Result := PUInt8(UInt32(p) + 1);
end;

// encode 16 bits unsigned int (lsb)
function ikcp_encode16u(p: PUInt8; w: UInt16): PUInt8;
begin
  PUInt16(p)^ := w;
  Result := PUInt8(UInt32(p) + 2);
end;

// decode 16 bits unsigned int (lsb)
function ikcp_decode16u(p: PUInt8; w: PUInt16): PUInt8;
begin
  w^ := PUInt16(p)^;
  Result := PUInt8(UInt32(p) + 2);
end;

// encode 32 bits unsigned int (lsb)
function ikcp_encode32u(p: PUInt8; dw: UInt32): PUInt8;
begin
  PUInt32(p)^ := dw;
  Result := PUInt8(UInt32(p) + 4);
end;

// decode 32 bits unsigned int (lsb)
function ikcp_decode32u(const p: PUInt8; dw: PUInt32): PUInt8;
begin
  dw^ := PUInt32(p)^;
  Result := PUInt8(UInt32(p) + 4);
end;

function _imin_(a, b: UInt32): UInt32;
begin
  if (a <= b) then
    Result := a
  else
    Result := b;
end;

function _imax_(a, b: UInt32): UInt32;
begin
  if (a >= b) then
    Result := a
  else
    Result := b;
end;

function _ibound_(lower, middle, upper: UInt32): UInt32;
begin
  Result := _imin_(_imax_(lower, middle), upper);
end;

function _itimediff(later, earlier: UInt32): Int32;
begin
  Result := later - earlier;
end;

//---------------------------------------------------------------------
// manage segment
//---------------------------------------------------------------------
var
  ikcp_malloc_hook: TMalloc = nil;
  ikcp_free_hook: TFree = nil;

// internal malloc
function ikcp_malloc(size: Int32): Pointer;
begin
  if (@ikcp_malloc_hook <> nil) then
    Result := ikcp_malloc_hook(size)
  else
    Result := GetMemory(size);
end;

// internal free
procedure ikcp_free(ptr: Pointer);
begin
  if (@ikcp_free_hook <> nil) then
    ikcp_free_hook(ptr)
  else
    FreeMemory(ptr);
end;

// redefine allocator
procedure ikcp_allocator(malloc: TMalloc; free: TFree);
begin
  @ikcp_malloc_hook := @malloc;
  @ikcp_free_hook := @free;
end;

// allocate a new kcp segment
function ikcp_segment_new(kcp: PKcpCb; size: Int32): PKcpSeg;
begin
  Result := PKcpSeg(ikcp_malloc(SizeOf(TKcpSeg) + size));
end;

procedure ikcp_segment_delete(kcp: PKcpCb; seg: PKcpSeg);
begin
  ikcp_free(Pointer(seg));
end;

procedure ikcp_log(kcp: PKcpCb; mask: Int32; const fmt: PTSTR; const param: array of const);
var
  buffer: {$IFDEF Unicode}AnsiString{$ELSE}string{$ENDIF};
begin
  if (((kcp^.logmask and mask) = 0) or (Pointer(@kcp^.writelog) = nil)) then Exit;
  buffer := Format(fmt, param) + #13#10;
  kcp^.writelog(PTSTR(buffer), kcp, kcp^.user);
end;

function ikcp_canlog(const kcp: PKcpCb; mask: Int32): Boolean;
begin
  Result := True;
  if (((mask and kcp^.logmask) = 0) or (Pointer(@kcp^.writelog) = nil)) then
    Result := False;
end;

function ikcp_output(kcp: PKcpCb; const data: PUInt8; size: Int32): Boolean;
begin
  assert(kcp <> nil, 'ikcp_output');
  assert(Pointer(@kcp^.output) <> nil, 'ikcp_output');
  Result := False;
  if (ikcp_canlog(kcp, CONST_IKCP_LOG_OUTPUT)) then
  begin
    ikcp_log(kcp, CONST_IKCP_LOG_OUTPUT, '[RO] %d bytes', [size]);
  end;
  if (size = 0) then Exit;
  Result := kcp^.output(data, size, kcp, kcp^.user);
end;

// output queue
procedure ikcp_qprint(name: PTSTR; head: PKcpSeg);
var
  p: PKcpSeg;
begin
{$IFDEF QPRINT}
  printf('<%s>: [', [name]);
  p := head^.next;
  while (p^.next <> head) do
  begin
    printf('%d %d', [p^.sn, Int32(p^.ts mod 10000)]);
    if (p^.next <> head) then printf(',', []);
    p := p^.next;
  end;
  printf(']' + #13#10, []);
{$ENDIF}
end;

//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
function ikcp_create(conv: UInt32; user: Pointer): PKcpCb;
begin
  Result := PKcpCb(ikcp_malloc(SizeOf(TKcpCb)));
  Result^.conv := conv;
  Result^.user := user;
  Result^.snd_una := 0;
  Result^.snd_nxt := 0;
  Result^.rcv_nxt := 0;
  Result^.ts_recent := 0;
  Result^.ts_lastack := 0;
  Result^.ts_probe := 0;
  Result^.probe_wait := 0;
  Result^.snd_wnd := IKCP_WND_SND;
  Result^.rcv_wnd := IKCP_WND_RCV;
  Result^.rmt_wnd := IKCP_WND_RCV;
  Result^.cwnd := 0;
  Result^.incr := 0;
  Result^.probe := 0;
  Result^.mtu := IKCP_MTU_DEF;
  Result^.mss := Result^.mtu - IKCP_OVERHEAD;
  Result^.stream := 0;

  Result^.buffer := PUInt8(ikcp_malloc((Result^.mtu + IKCP_OVERHEAD) * 3));
  if (Result^.buffer = nil) then
  begin
    ikcp_free(Result);
    Result := nil;
    Exit;
  end;

  iqueue_init(@Result^.snd_queue);
  iqueue_init(@Result^.rcv_queue);
  iqueue_init(@Result^.snd_buf);
  iqueue_init(@Result^.rcv_buf);
  Result^.nrcv_buf := 0;
  Result^.nsnd_buf := 0;
  Result^.nrcv_que := 0;
  Result^.nsnd_que := 0;
  Result^.state := 0;
  Result^.acklist := nil;
  Result^.ackblock := 0;
  Result^.ackcount := 0;
  Result^.rx_srtt := 0;
  Result^.rx_rttval := 0;
  Result^.rx_rto := IKCP_RTO_DEF;
  Result^.rx_minrto := IKCP_RTO_MIN;
  Result^.current := 0;
  Result^.interval := IKCP_INTERVAL_;
  Result^.ts_flush := IKCP_INTERVAL_;
  Result^.nodelay := 0;
  Result^.updated := 0;
  Result^.logmask := 0;
  Result^.ssthresh := IKCP_THRESH_INIT;
  Result^.fastresend := 0;
  Result^.nocwnd := 0;
  Result^.xmit := 0;
  Result^.dead_link := IKCP_DEADLINK;
  @Result^.output := nil;
  @Result^.writelog := nil;
end;

//---------------------------------------------------------------------
// release a new kcpcb
//---------------------------------------------------------------------
procedure ikcp_release(kcp: PkcpCb);
var
  seg: PKcpSeg;
begin
  assert(kcp <> nil, 'ikcp_release');
  if (kcp <> nil) then
  begin
    while (not iqueue_is_empty(@kcp^.snd_buf)) do
    begin
      seg := iqueue_entry(kcp^.snd_buf.next);
      iqueue_del(seg);
      ikcp_segment_delete(kcp, seg);
    end;
    while (not iqueue_is_empty(@kcp^.rcv_buf)) do
    begin
      seg := iqueue_entry(kcp^.rcv_buf.next);
      iqueue_del(seg);
      ikcp_segment_delete(kcp, seg);
    end;
    while (not iqueue_is_empty(@kcp^.snd_queue)) do
    begin
      seg := iqueue_entry(kcp^.snd_queue.next);
      iqueue_del(seg);
      ikcp_segment_delete(kcp, seg);
    end;
    while (not iqueue_is_empty(@kcp^.rcv_queue)) do
    begin
      seg := iqueue_entry(kcp^.rcv_queue.next);
      iqueue_del(seg);
      ikcp_segment_delete(kcp, seg);
    end;
    if (kcp^.buffer <> nil) then
      ikcp_free(Pointer(kcp^.buffer));
    kcp^.nrcv_buf := 0;
    kcp^.nsnd_buf := 0;
    kcp^.nrcv_que := 0;
    kcp^.nsnd_que := 0;
    kcp^.ackcount := 0;
    kcp^.buffer := nil;
    kcp^.acklist := nil;
    ikcp_free(kcp);
  end;
end;

//---------------------------------------------------------------------
// set output callback, which will be invoked by kcp
//---------------------------------------------------------------------
procedure ikcp_setoutput(kcp: PkcpCb; output: TOutPut);
begin
  @kcp^.output := @output;
end;

//---------------------------------------------------------------------
// user/upper level recv: returns size, returns below zero for EAGAIN
//---------------------------------------------------------------------
function ikcp_recv(kcp: PkcpCb; buffer: PUInt8; len: Int32): Int32;
var
  seg, p: PKcpSeg;
  ispeek, recover: Boolean;
  peeksize, fragment: Int32;
begin
  assert(kcp <> nil, 'ikcp_recv 1');
  ispeek := len < 0;

  if (iqueue_is_empty(@kcp^.rcv_queue)) then Exit(-1);

  if (len < 0) then len := -len;

  peeksize := ikcp_peeksize(kcp);

  if (peeksize < 0) then Exit(-2);

  if (peeksize > len) then Exit(-3);

  recover := False;
  if (kcp^.nrcv_que >= kcp^.rcv_wnd) then recover := True;

  // merge fragment
  len := 0;
  p := kcp^.rcv_queue.next;
  while (p <> @kcp^.rcv_queue) do
  begin
    seg := iqueue_entry(p);
    p := p^.next;
    if (buffer <> nil) then
    begin
      memcpy(buffer, @seg^.data, seg^.len);
      Inc(buffer, seg^.len);
    end;

    Inc(len, seg^.len);
    fragment := seg^.frg;

    if (ikcp_canlog(kcp, CONST_IKCP_LOG_RECV)) then
    begin
      ikcp_log(kcp, CONST_IKCP_LOG_RECV, 'recv sn = %d', [seg^.sn]);
    end;

    if (not ispeek) then
    begin
      iqueue_del(seg);
      ikcp_segment_delete(kcp, seg);
      Dec(kcp^.nrcv_que);
    end;

    if (fragment = 0) then Break;
  end;

  assert(len = peeksize, 'ikcp_recv 2');

  // move available data from rcv_buf -> rcv_queue
  while (not iqueue_is_empty(@kcp^.rcv_buf)) do
  begin
    seg := iqueue_entry(kcp^.rcv_buf.next);
    if ((seg^.sn = kcp^.rcv_nxt) and (kcp^.nrcv_que < kcp^.rcv_wnd)) then
    begin
      iqueue_del(seg);
      Dec(kcp^.nrcv_buf);
      iqueue_add_tail(seg, @kcp^.rcv_queue);
      Inc(kcp^.nrcv_que);
      Inc(kcp^.rcv_nxt);
    end
    else Break;
  end;

  // fast recover
  if ((kcp^.nrcv_que < kcp^.rcv_wnd) and recover) then
  begin
    kcp^.probe := kcp^.probe or IKCP_ASK_TELL;
  end;
  Result := len;
end;

//---------------------------------------------------------------------
// peek data size
//---------------------------------------------------------------------
function ikcp_peeksize(const kcp: PkcpCb): Int32;
var
  seg: PKcpSeg;
begin
  if (iqueue_is_empty(@kcp^.rcv_queue)) then Exit(-1);

  seg := iqueue_entry(kcp^.rcv_queue.next);
  if (seg^.frg = 0) then Exit(seg^.len);

  if (kcp^.nrcv_que < seg^.frg + 1) then Exit(-1);

  Result := 0;
  seg := kcp^.rcv_queue.next;
  while (seg <> @kcp^.rcv_queue) do
  begin
    Result := Result + seg^.len;
    if (seg^.frg = 0) then Break;
    seg := seg^.next;
  end;
end;
//---------------------------------------------------------------------
// user/upper level send, returns below zero for error
//---------------------------------------------------------------------
function ikcp_send(kcp: PkcpCb; const buf: PUInt8; len: Int32): Int32;
var
  seg, old: PKcpSeg;
  capacity, extend, count, i, size: Int32;
  buffer: PUInt8;
begin
  assert(kcp^.mss > 0, 'ikcp_send 0');
  buffer := buf;
  if (len < 0) then Exit(-1);

	// append to previous segment in streaming mode (if possible)
  if (kcp^.stream <> 0) then
  begin
    if (not iqueue_is_empty(@kcp^.snd_queue)) then
    begin
      old := iqueue_entry(kcp^.snd_queue.prev);
      if (old^.len < kcp^.mss) then
      begin
        capacity := kcp^.mss - old^.len;
        if (len < capacity) then
          extend := len
        else
          extend := capacity;
        seg := ikcp_segment_new(kcp, old^.len + extend);
        assert(seg <> nil, 'ikcp_send 1');
        if (seg = nil) then Exit(-2);
        iqueue_add_tail(seg, @kcp^.snd_queue);
        memcpy(@seg^.data, @old^.data, old^.len);
        if (buffer <> nil) then
        begin
          memcpy(Pointer(UInt32(@seg^.data) + old^.len), buffer, extend);
          Inc(buffer, extend);
        end;
        seg^.len := old^.len + extend;
        seg^.frg := 0;
        Dec(len, extend);
        iqueue_del_init(old);
        ikcp_segment_delete(kcp, old);
      end;
    end;
    if (len <= 0) then Exit(0);
  end;
  if (len <= kcp^.mss) then
    count := 1
  else
    count := (len + kcp^.mss - 1) div kcp^.mss;

  if (count > 255) then Exit(-2);

  if (count = 0) then count := 1;

  // fragment
  for i := 0 to count - 1 do
  begin
    if (len > kcp^.mss) then
      size := kcp^.mss
    else
      size := len;
    seg := ikcp_segment_new(kcp, size);
    assert(seg <> nil, 'ikcp_send 2');
    if (seg = nil) then Exit(-2);
    if ((buffer <> nil) and (len > 0)) then
    begin
      memcpy(@seg^.data, buffer, size);
    end;
    seg^.len := size;
    if (kcp^.stream = 0) then
      seg^.frg := count - i - 1
    else
      seg^.frg := 0;
    iqueue_init(seg);
    iqueue_add_tail(seg, @kcp^.snd_queue);
    Inc(kcp^.nsnd_que);
    if (buffer <> nil) then Inc(buffer, size);
    Dec(len, size);
  end;
  Result := 0;
end;
//---------------------------------------------------------------------
// parse ack
//---------------------------------------------------------------------
procedure ikcp_update_ack(kcp: PkcpCb; rtt: Int32);
var
  rto: Int32;
  delta: Int32;
begin
  rto := 0;
  if (kcp^.rx_srtt = 0) then
  begin
    kcp^.rx_srtt := rtt;
    kcp^.rx_rttval := rtt div 2;
  end
  else begin
    delta := rtt - kcp^.rx_srtt;
    if (delta < 0) then delta := -delta;
    kcp^.rx_rttval := (3 * kcp^.rx_rttval + delta) div 4;
    kcp^.rx_srtt := (7 * kcp^.rx_srtt + rtt) div 8;
    if (kcp^.rx_srtt < 1) then kcp^.rx_srtt := 1;
  end;
  rto := kcp^.rx_srtt + _imax_(1, 4 * kcp^.rx_rttval);
  kcp^.rx_rto := _ibound_(kcp^.rx_minrto, rto, IKCP_RTO_MAX);
end;

procedure ikcp_shrink_buf(kcp: PKcpCb);
var
  seg: PKcpSeg;
begin
  seg := iqueue_entry(kcp^.snd_buf.next);
  if (seg <> @kcp^.snd_buf) then
    kcp^.snd_una := seg^.sn
  else
    kcp^.snd_una := kcp^.snd_nxt;
end;

procedure ikcp_parse_ack(kcp: PkcpCb; sn: UInt32);
var
  seg, next: PKcpSeg;
begin
  if ((_itimediff(sn, kcp^.snd_una) < 0) or (_itimediff(sn, kcp^.snd_nxt) >= 0)) then Exit;

  seg := iqueue_entry(kcp^.snd_buf.next);
  while (seg <> @kcp^.snd_buf) do
  begin
    next := seg^.next;
    if (sn = seg^.sn) then
    begin
      iqueue_del(seg);
      ikcp_segment_delete(kcp, seg);
      Dec(kcp^.nsnd_buf);
      Break
    end;
    if (_itimediff(sn, seg^.sn) < 0) then Break;
    seg := next;
  end;
end;

procedure ikcp_parse_una(kcP: PkcpCb; una: UInt32);
var
  seg, next: PKcpSeg;
begin
  seg := iqueue_entry(kcp^.snd_buf.next);
  while (seg <> @kcp^.snd_buf) do
  begin
    next := seg^.next;
    if (_itimediff(una, seg^.sn) > 0) then
    begin
      iqueue_del(seg);
      ikcp_segment_delete(kcp, seg);
      Dec(kcp^.nsnd_buf);
    end
    else Break;
    seg := next;
  end;
end;

procedure ikcp_parse_fastack(kcp: PkcpCb; sn: UInt32);
var
  seg, next: PKcpSeg;
begin
  if ((_itimediff(sn, kcp^.snd_una) < 0) or (_itimediff(sn, kcp^.snd_nxt) >= 0)) then Exit;

  seg := iqueue_entry(kcp^.snd_buf.next);
  while (seg <> @kcp^.snd_buf) do
  begin
    next := seg^.next;
    if (_itimediff(sn, seg^.sn) < 0) then
      Break
    else if (sn <> seg^.sn) then
      Inc(seg^.fastack);
    seg := next;
  end;
end;

{$PointerMath ON}
procedure ikcp_ack_push(kcp: PkcpCb; sn: UInt32; ts: UInt32);
var
  newsize, newblock, x: UInt32;
  ptr, acklist: PUInt32;
begin
  newsize := kcp^.ackcount + 1;
  if (newsize > kcp^.ackblock) then
  begin
    newblock := 8;
    while (newblock < newsize) do newblock := newblock shl 1;
    acklist := PUInt32(ikcp_malloc(newblock * SizeOf(UInt32) * 2));

    if (acklist = nil) then
    begin
      assert(acklist <> nil, 'ikcp_ack_push 0');
      Abort();
    end;

    if (kcp^.acklist <> nil) then
    begin
      for x := 0 to kcp^.ackcount - 1 do
      begin
        acklist[x * 2 + 0] := kcp^.acklist[x * 2 + 0];
        acklist[x * 2 + 1] := kcp^.acklist[x * 2 + 1];
      end;
      ikcp_free(kcp^.acklist);
    end;

    kcp^.acklist := acklist;
    kcp^.ackblock := newblock;
  end;
  ptr := @kcp^.acklist[kcp^.ackcount * 2];
  ptr[0] := sn;
  ptr[1] := ts;
  Inc(kcp^.ackcount);
end;

procedure ikcp_ack_get(const kcp: PkcpCb; p: UInt32; sn: PUInt32; ts: PUInt32);
begin
  if (sn <> nil) then sn^ := kcp^.acklist[p * 2 + 0];
  if (ts <> nil) then ts^ := kcp^.acklist[p * 2 + 1];
end;
{$PointerMath OFF}

//---------------------------------------------------------------------
// parse data(fixed)
//---------------------------------------------------------------------
procedure ikcp_parse_data(kcp: PkcpCb; newseg: PKcpSeg);
var
  prev, seg: PKcpSeg;
  sn: UInt32;
  re: Boolean;
begin
  sn := newseg^.sn;
  re := False;
  if ((_itimediff(sn, kcp^.rcv_nxt + kcp^.rcv_wnd) >= 0) or
      (_itimediff(sn, kcp^.rcv_nxt) < 0)) then
  begin
    ikcp_segment_delete(kcp, newseg);
    Exit;
  end;

  seg := iqueue_entry(kcp^.rcv_buf.prev);
  while (seg <> @kcp^.rcv_buf) do
  begin
    prev := seg^.prev;
    if (seg^.sn = sn) then
    begin
      re := True;
      Break;
    end;
    if (_itimediff(sn, seg^.sn) > 0) then Break;
    seg := prev;
  end;

  if (not re) then
  begin
    iqueue_init(newseg);
    iqueue_add(newseg, seg);
    Inc(kcp^.nrcv_buf);
  end
  else begin
    ikcp_segment_delete(kcp, newseg);
  end;

{$IFDEF QPRINT}
  ikcp_qprint('rcvbuf', @kcp^.rcv_buf);
  printf('rcv_nxt = %d' + #13#10, [kcp^.rcv_nxt]);
{$ENDIF}

  // move available data from rcv_buf -> rcv_queue
  while (not iqueue_is_empty(@kcp^.rcv_buf)) do
  begin
    seg := iqueue_entry(kcp^.rcv_buf.next);
    if ((seg^.sn = kcp^.rcv_nxt) and (kcp^.nrcv_que < kcp^.rcv_wnd)) then
    begin
      iqueue_del(seg);
      Dec(kcp^.nrcv_buf);
      iqueue_add_tail(seg, @kcp^.rcv_queue);
      Inc(kcp^.nrcv_que);
      Inc(kcp^.rcv_nxt);
    end
    else Break;
  end;
{$IFDEF QPRINT}
  ikcp_qprint('queue', @kcp^.rcv_queue);
  printf('rcv_nxt = %d' + #13#10, [kcp^.rcv_nxt]);
  printf('snd(buf=%d, queue=%d)' + #13#10, [kcp^.nsnd_buf, kcp^.nsnd_que]);
  printf('rcv(buf=%d, queue=%d)' + #13#10, [kcp^.nrcv_buf, kcp^.nrcv_que]);
{$ENDIF}
end;
//---------------------------------------------------------------------
// input data
//---------------------------------------------------------------------
function ikcp_input(kcp: PKcpCb; const buf: PUInt8; size: UInt32): Int32;
var
  flag: Boolean;
  una, maxack, mss: UInt32;
  ts, sn, len, una_, conv: UInt32;
  wnd: UInt16;
  cmd, frg: UInt8;
  seg: PKcpSeg;
  data: PUInt8;
begin
  data := buf;
  una := kcp^.snd_una;
  maxack := 0;
  flag := False;
  if (ikcp_canlog(kcp, CONST_IKCP_LOG_INPUT)) then
    ikcp_log(kcp, CONST_IKCP_LOG_INPUT, '[RI] %d bytes', [size]);

  if ((data = nil) or (size < 24)) then Exit(-1);

  while (True) do
  begin
    if (size < IKCP_OVERHEAD) then Break;

    data := ikcp_decode32u(data, @conv);
    if (conv <> kcp^.conv) then Exit(-1);

		data := ikcp_decode8u(data, @cmd);
		data := ikcp_decode8u(data, @frg);
		data := ikcp_decode16u(data, @wnd);
		data := ikcp_decode32u(data, @ts);
		data := ikcp_decode32u(data, @sn);
		data := ikcp_decode32u(data, @una_);
		data := ikcp_decode32u(data, @len);

    Dec(size, IKCP_OVERHEAD);

    if (size < len) then Exit(-2);

    if ((cmd <> IKCP_CMD_PUSH) and (cmd <> IKCP_CMD_ACK) and (cmd <> IKCP_CMD_WASK) and
      (cmd <> IKCP_CMD_WINS)) then Exit(-3);

    kcp^.rmt_wnd := wnd;
    ikcp_parse_una(kcp, una_);
    ikcp_shrink_buf(kcp);

    if (cmd = IKCP_CMD_ACK) then
    begin
      if (_itimediff(kcp^.current, ts) >= 0) then
        ikcp_update_ack(kcp, _itimediff(kcp^.current, ts));
      ikcp_parse_ack(kcp, sn);
      ikcp_shrink_buf(kcp);
      if (not flag) then
      begin
        flag := True;
        maxack := sn;
      end
      else begin
        if (_itimediff(sn, maxack) > 0) then maxack := sn;
      end;
      if (ikcp_canlog(kcp, CONST_IKCP_LOG_IN_ACK)) then
      begin
        ikcp_log(kcp, CONST_IKCP_LOG_IN_DATA, 'input ack: sn=%d rtt=%d rto=%d', [sn,
          _itimediff(kcp^.current, ts), kcp^.rx_rto]);
      end;
    end
    else if (cmd = IKCP_CMD_PUSH) then
    begin
      if (ikcp_canlog(kcp, CONST_IKCP_LOG_IN_ACK)) then
      begin
        ikcp_log(kcp, CONST_IKCP_LOG_IN_DATA, 'input psh: sn=%d ts=%d', [sn, ts]);
      end;
      if (_itimediff(sn, kcp^.rcv_nxt + kcp^.rcv_wnd) < 0) then
      begin
        ikcp_ack_push(kcp, sn, ts);
        if (_itimediff(sn, kcp^.rcv_nxt) >= 0) then
        begin
          seg := ikcp_segment_new(kcp, len);
          seg^.conv := conv;
          seg^.cmd := cmd;
          seg^.frg := frg;
          seg^.wnd := wnd;
          seg^.ts := ts;
          seg^.sn := sn;
          seg^.una := una_;
          seg^.len := len;

          if (len > 0) then
            memcpy(@seg^.data, data, len);

          ikcp_parse_data(kcp, seg);
        end;
      end;
    end
    else if (cmd = IKCP_CMD_WASK) then
    begin
      // ready to send back IKCP_CMD_WINS in ikcp_flush
			// tell remote my window size
      kcp^.probe := kcp^.probe or IKCP_ASK_TELL;
      if (ikcp_canlog(kcp, CONST_IKCP_LOG_IN_PROBE)) then
      begin
        ikcp_log(kcp, CONST_IKCP_LOG_IN_PROBE, 'input probe', []);
      end;
    end
    else if (cmd = IKCP_CMD_WINS) then
    begin
      // do nothing
      if (ikcp_canlog(kcp, CONST_IKCP_LOG_IN_WINS)) then
      begin
        ikcp_log(kcp, CONST_IKCP_LOG_IN_WINS, 'input wins: %d', [wnd]);
      end;
    end
    else Exit(-3);

    Inc(data, len);
    Dec(size, len);
  end;

  if (flag) then ikcp_parse_fastack(kcp, maxack);

  if (_itimediff(kcp^.snd_una, una) > 0) then
  begin
    if (kcp^.cwnd < kcp^.rmt_wnd) then
    begin
      mss := kcp^.mss;
      if (kcp^.cwnd < kcp^.ssthresh) then
      begin
        Inc(kcp^.cwnd);
        Inc(kcp^.incr, mss);
      end
      else begin
        if (kcp^.incr < mss) then kcp^.incr := mss;
        kcp^.incr := kcp^.incr + ((mss * mss) div kcp^.incr) + (mss div 16);
        if ((kcp^.cwnd + 1) * mss <= kcp^.incr) then Inc(kcp^.cwnd);
      end;
      if (kcp^.cwnd > kcp^.rmt_wnd) then
      begin
        kcp^.cwnd := kcp^.rmt_wnd;
        kcp^.incr := kcp^.rmt_wnd * mss;
      end;
    end;
  end;
  Result := 0;
end;
//---------------------------------------------------------------------
// ikcp_encode_seg
//---------------------------------------------------------------------
function ikcp_encode_seg(ptr: PUInt8; const seg: PKcpSeg): PUInt8;
begin
	ptr := ikcp_encode32u(ptr, seg^.conv);
	ptr := ikcp_encode8u(ptr, UInt8(seg^.cmd));
	ptr := ikcp_encode8u(ptr, UInt8(seg^.frg));
	ptr := ikcp_encode16u(ptr, UInt16(seg^.wnd));
	ptr := ikcp_encode32u(ptr, seg^.ts);
	ptr := ikcp_encode32u(ptr, seg^.sn);
	ptr := ikcp_encode32u(ptr, seg^.una);
	ptr := ikcp_encode32u(ptr, seg^.len);
  Result := ptr;
end;

function ikcp_wnd_unused(const kcp: PkcpCb): Int32;
begin
  Result := 0;
  if (kcp^.nrcv_que < kcp^.rcv_wnd) then Result := kcp^.rcv_wnd - kcp^.nrcv_que;
end;
//---------------------------------------------------------------------
// ikcp_flush
//---------------------------------------------------------------------
procedure ikcp_flush(kcp: PkcpCb);
var
  current: UInt32;
  buffer, ptr: PUInt8;
  count, size, i: Int32;
  resent, cwnd, rtomin: UInt32;
  change, lost: Int32;
  newseg, p, segment: PKcpSeg;
  seg: TKcpSeg;
  needsend: Boolean;
  size_, need: Int32;
  inflight: UInt32;
begin
  current := kcp^.current;
  buffer := kcp^.buffer;
  ptr := buffer;
  change := 0;
  lost := 0;

  // 'ikcp_update' haven't been called.
  if (kcp^.updated = 0) then Exit;

	seg.conv := kcp^.conv;
	seg.cmd := IKCP_CMD_ACK;
	seg.frg := 0;
	seg.wnd := ikcp_wnd_unused(kcp);
	seg.una := kcp^.rcv_nxt;
	seg.len := 0;
	seg.sn := 0;
	seg.ts := 0;
	// flush acknowledges
  count := kcp^.ackcount;
  for i := 0 to count -1 do
  begin
    size := UInt32(ptr) - UInt32(buffer);
    if (size + IKCP_OVERHEAD > kcp^.mtu) then
    begin
      ikcp_output(kcp, buffer, size);
      ptr := buffer;
    end;
    ikcp_ack_get(kcp, i, @seg.sn, @seg.ts);
    ptr := ikcp_encode_seg(ptr, @seg);
  end;

  kcp^.ackcount := 0;

	// probe window size (if remote window size equals zero)
  if (kcp^.rmt_wnd = 0) then
  begin
    if (kcp^.probe_wait = 0) then
    begin
      kcp^.probe_wait := IKCP_PROBE_INIT;
      kcp^.ts_probe := kcp^.current + kcp^.probe_wait;
    end
    else begin
      if (_itimediff(kcp^.current, kcp^.ts_probe) >= 0) then
      begin
        if (kcp^.probe_wait < IKCP_PROBE_INIT) then
          kcp^.probe_wait := IKCP_PROBE_INIT;
        kcp^.probe_wait := kcp^.probe_wait div 2;
        if (kcp^.probe_wait > IKCP_PROBE_LIMIT) then
          kcp^.probe_wait := IKCP_PROBE_LIMIT;
        kcp^.ts_probe := kcp^.current + kcp^.probe_wait;
        kcp^.probe := kcp^.probe or IKCP_ASK_SEND;
      end;
    end;
  end
  else begin
    kcp^.ts_probe := 0;
    kcp^.probe_wait := 0;
  end;

  // flush window probing commands
  if ((kcp^.probe and IKCP_ASK_SEND) > 0) then
  begin
    seg.cmd := IKCP_CMD_WASK;
    size := UInt32(ptr) - UInt32(buffer);
    if (size + IKCP_OVERHEAD > kcp^.mtu) then
    begin
      ikcp_output(kcp, buffer, size);
      ptr := buffer;
    end;
    ptr := ikcp_encode_seg(ptr, @seg);
  end;

  // flush window probing commands
  if ((kcp^.probe and IKCP_ASK_TELL) > 0) then
  begin
    seg.cmd := IKCP_CMD_WINS;
    size := UInt32(ptr) - UInt32(buffer);
    if (size + IKCP_OVERHEAD > kcp^.mtu) then
    begin
      ikcp_output(kcp, buffer, size);
      ptr := buffer;
    end;
    ptr := ikcp_encode_seg(ptr, @seg);
  end;

  kcp^.probe := 0;

  // calculate window size
  cwnd := _imin_(kcp^.snd_wnd, kcp^.rmt_wnd);
  if (kcp^.nocwnd = 0) then cwnd := _imin_(kcp^.cwnd, cwnd);

  // move data from snd_queue to snd_buf
  while (_itimediff(kcp^.snd_nxt, kcp^.snd_una + cwnd) < 0) do
  begin
    if (iqueue_is_empty(@kcp^.snd_queue)) then Break;

    newseg := iqueue_entry(kcp^.snd_queue.next);

    iqueue_del(newseg);
    iqueue_add_tail(newseg, @kcp^.snd_buf);
		Dec(kcp^.nsnd_que);
		Inc(kcp^.nsnd_buf);

		newseg^.conv := kcp^.conv;
		newseg^.cmd := IKCP_CMD_PUSH;
		newseg^.wnd := seg.wnd;
		newseg^.ts := current;
		newseg^.sn := kcp^.snd_nxt;
    Inc(kcp^.snd_nxt);
		newseg^.una := kcp^.rcv_nxt;
		newseg^.resendts := current;
		newseg^.rto := kcp^.rx_rto;
		newseg^.fastack := 0;
		newseg^.xmit := 0;
  end;

  // calculate resent
  if (kcp^.fastresend > 0) then
    resent := kcp^.fastresend
  else
    resent := $FFFFFFFF;
  if (kcp^.nodelay = 0) then
    rtomin := kcp^.rx_rto shr 3
  else
    rtomin := 0;

	// flush data segment
  p := kcp^.snd_buf.next;
  while (p <> @kcp^.snd_buf) do
  begin
    segment := iqueue_entry(p);
    needsend := False;
    if (segment^.xmit = 0) then
    begin
      needsend := True;
      Inc(segment^.xmit);
      segment^.rto := kcp^.rx_rto;
      segment^.resendts := current + segment^.rto + rtomin;
    end
    else if (_itimediff(current, segment^.resendts) >= 0) then
    begin
      needsend := True;
      Inc(segment^.xmit);
      Inc(kcp^.xmit);
      if (kcp^.nodelay = 0) then
        segment^.rto := segment^.rto + kcp^.rx_rto
      else
        segment^.rto := segment^.rto + (kcp^.rx_rto div 2);
      segment^.resendts := current + segment^.rto;
      lost := 1;
    end
    else if (segment^.fastack >= resent) then
    begin
      needsend := True;
      Inc(segment^.xmit);
      segment^.fastack := 0;
      segment^.resendts := current + segment^.rto;
      Inc(change);
    end;

    if (needsend) then
    begin
      segment^.ts := current;
      segment^.wnd := seg.wnd;
      segment^.una := kcp^.rcv_nxt;

      size_ := UInt32(ptr) - UInt32(buffer);
      need := IKCP_OVERHEAD + segment^.len;

      if (size_ + need > kcp^.mtu) then
      begin
        ikcp_output(kcp, buffer, size_);
        ptr := buffer;
      end;

      ptr := ikcp_encode_seg(ptr, segment);

      if (segment^.len > 0) then
      begin
        memcpy(ptr, @segment^.data, segment^.len);
        Inc(ptr, segment^.len);
      end;

      if (segment^.xmit >= kcp^.dead_link) then
        kcp^.state := UInt32(-1);
    end;
    p := p^.next;
  end;

  // flash remain segments
  size := UInt32(ptr) - UInt32(buffer);
  if (size > 0) then ikcp_output(kcp, buffer, size);

  // update ssthresh
  if (change <> 0) then
  begin
    inflight := kcp^.snd_nxt - kcp^.snd_una;
    kcp^.ssthresh := inflight div 2;
    if (kcp^.ssthresh < IKCP_THRESH_MIN) then kcp^.ssthresh := IKCP_THRESH_MIN;
    kcp^.cwnd := kcp^.ssthresh + resent;
    kcp^.incr := kcp^.cwnd * kcp^.mss;
  end;

  if (lost <> 0) then
  begin
    kcp^.ssthresh := cwnd div 2;
    if (kcp^.ssthresh < IKCP_THRESH_MIN) then kcp^.ssthresh := IKCP_THRESH_MIN;
    kcp^.cwnd := 1;
    kcp^.incr := kcp^.mss;
  end;

	if (kcp^.cwnd < 1) then
  begin
		kcp^.cwnd := 1;
		kcp^.incr := kcp^.mss;
  end;
end;

//---------------------------------------------------------------------
// update state (call it repeatedly, every 10ms-100ms), or you can ask
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec.
//---------------------------------------------------------------------
procedure ikcp_update(kcp: PkcpCb; current: UInt32);
var
  slap: Int32;
begin
  kcp^.current := current;
  if (kcp^.updated = 0) then
  begin
    kcp^.updated := 1;
    kcp^.ts_flush := kcp^.current;
  end;

  slap := _itimediff(kcp^.current, kcp^.ts_flush);

  if ((slap >= 10000) or (slap < -10000)) then
  begin
    kcp^.ts_flush := kcp^.current;
    slap := 0;
  end;

  if (slap >= 0) then
  begin
    kcp^.ts_flush := kcp^.ts_flush + kcp^.interval;
    if (_itimediff(kcp^.current, kcp^.ts_flush) >= 0) then
      kcp^.ts_flush := kcp^.current + kcp^.interval;
    ikcp_flush(kcp);
  end;
end;

//---------------------------------------------------------------------
// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to
// schedule ikcp_update (eg. implementing an epoll-like mechanism,
// or optimize ikcp_update when handling massive kcp connections)
//---------------------------------------------------------------------
function ikcp_check(const kcp: PkcpCb; current: UInt32): UInt32;
var
  ts_flush, minimal: UInt32;
  tm_flush, tm_packet, diff: Int32;
  seg: PKcpSeg;
begin
  ts_flush := kcp^.ts_flush;
  tm_flush := $7fffffff;
  tm_packet := $7fffffff;
  minimal := 0;
  if (kcp^.updated = 0) then Exit(current);

  if ((_itimediff(current, ts_flush) >= 10000) or
    (_itimediff(current, ts_flush) < -10000)) then ts_flush := current;

  if (_itimediff(current, ts_flush) >= 0) then Exit(current);

  tm_flush := _itimediff(ts_flush, current);

  seg := kcp^.snd_buf.next;
  while(seg <> @kcp^.snd_buf) do
  begin
    diff := _itimediff(seg^.resendts, current);
    if (diff <= 0) then Exit(current);
    if (diff < tm_packet) then tm_packet := diff;
    seg := seg^.next;
  end;

  if (tm_packet < tm_flush) then
    minimal := UInt32(tm_packet)
  else
    minimal := UInt32(tm_flush);
  if (minimal >= kcp^.interval) then minimal := kcp^.interval;

  Result := current + minimal;
end;

function ikcp_setmtu(kcp: PKcpCb; mtu: Int32): Int32;
var
  buffer: PUInt8;
begin
  if ((mtu < 50) or (mtu < IKCP_OVERHEAD)) then Exit(-1);
  buffer := PUInt8(ikcp_malloc((mtu + IKCP_OVERHEAD) * 3));
  if (buffer = nil) then Exit(-2);
  kcp^.mtu := mtu;
  kcp^.mss := kcp^.mtu - IKCP_OVERHEAD;
  ikcp_free(kcp^.buffer);
  kcp^.buffer := buffer;
  Result := 0;
end;

function ikcp_interval(kcp: PkcpCb; interval: Int32): Int32;
begin
  if (interval > 5000) then
    interval := 5000
  else if (interval < 10) then
    interval := 10;
  kcp^.interval := interval;
  Result := 0;
end;

function ikcp_nodelay(kcp: PkcpCb; nodelay: Int32; interval: Int32; resend: Int32; nc: Int32): Int32;
begin
  if (nodelay >= 0) then
  begin
    kcp^.nodelay := nodelay;
    if (nodelay <> 0) then
      kcp^.rx_minrto := IKCP_RTO_NDL
    else
      kcp^.rx_minrto := IKCP_RTO_MIN;
  end;
  if (interval >= 0) then
  begin
    if (interval > 5000) then
      interval := 5000
    else if (interval < 10) then
      interval := 10;
    kcp^.interval := interval;
  end;
  if (resend >= 0) then kcp^.fastresend := resend;
  if (nc >= 0) then kcp^.nocwnd := nc;
  Result := 0;
end;

function ikcp_wndsize(kcp: PkcpCb; sndwnd: Int32; rcvwnd: Int32): Int32;
begin
  if (kcp <> nil) then
  begin
    if (sndwnd > 0) then kcp^.snd_wnd := sndwnd;
    if (rcvwnd > 0) then kcp^.rcv_wnd := rcvwnd;
  end;
  Result := 0;
end;

function ikcp_waitsnd(const kcp: PKcpCb): Int32;
begin
  Result := kcp^.nsnd_buf + kcp^.nsnd_que;
end;

function ikcp_getconv(const ptr: Pointer): UInt32;
begin
  ikcp_decode32u(ptr, @Result);
end;

end.
