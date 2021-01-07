import random
import struct
from enum import Enum

from USocket import UnreliableSocket
import time
import threading
from queue import SimpleQueue, Empty
from math import log
import json

SEND_WAIT = 0.005  # ACK等数据的时间
SEND_FIN_WAIT = 0.5  # 下次尝试发FIN的时间
RTT_ = 0.95  # RTT对于上次的保留系数，越小变化越剧烈
INCREASE_ = 0  # 升窗界线
DECREASE_ = 3  # 降窗界线
EXTRA_ACK_WAIT = 0.75  # 额外的等待ACK的时间
SYN_ACK_WAIT = 5  # 等待回复SYN_ACK的时间
MAX_PKT_LEN = 1024  # 最大包长度
BOMB_RATE = 0.15  # 超时包长度占窗口的比例，强制降窗


class RDTEventType(Enum):
    SYN = 0  # 对方SYN, 下同
    SYN_ACK = 1
    ACK = 2
    FIN = 3
    FIN_ACK = 4
    RST = 5
    SAK = 6
    CORRUPTION = 7
    SEND_ACK = 8  # 需要 send ACK
    SEND_FIN = 10  # 需要 send FIN
    UNKNOWN_ERROR = 11  # 在 send loop 或 recv loop 捕获的异常，未知类型
    ACK_TIMEOUT = 12  # 等待ACK超时
    CONNECT = 13  # 上层调用CONNECT
    SEND = 14  # 上层调用SEND
    LISTEN_CLOSE = 15  # 对监听的调用 CLOSE
    SIMPLE_CLOSE = 16  # 调用CLOSE
    DESTROY_SIMPLE = 17  # 销毁单个连接
    DESTROY_ALL = 18  # 尝试结束所有循环线程，探测到可以结束时会引发VANISH事件
    VANISH = 19  # 真正结束所有线程，这个事件会break掉事件循环


class RDTConnectionStatus(Enum):
    SYN_ = 0  # 收到过SYN了
    SYN_ACK_ = 1  # 收到过SYN_ACK了
    ACK_ = 2  # 收到过ACK了
    FIN = 3  # 发过FIN了
    FIN_ = 4  # 收到过FIN了
    FIN_ACK_ = 5  # 收到过FIN_ACK了


class RDTEvent:
    """
    事件的实体类，body有多种类型
    """

    def __init__(self, e_type: RDTEventType, body: any):
        self.type = e_type
        self.body = body


class RDTTimer:
    """
    计时器实体类
    """

    def __init__(self, timeout: float, e: RDTEvent):
        self.start_time = time.time()
        self.event = e
        self.target_time = self.start_time + timeout
        self.active = True


class RDTPacket:
    """
    包的实体类
    """

    def __init__(self, remote, SEQ, SEQ_ACK, SYN=0, ACK=0, FIN=0, RST=0, SAK=0, _=0, PAYLOAD=bytes()):
        self.SYN = SYN
        self.ACK = ACK
        self.FIN = FIN
        self.RST = RST
        self.SAK = SAK
        self._ = _
        self.SEQ = SEQ
        self.SEQ_ACK = SEQ_ACK
        self.LEN = len(PAYLOAD)
        self.CHECKSUM = 0
        self.PAYLOAD: bytes = PAYLOAD
        self.PAYLOAD_REAL: bytes = self.PAYLOAD
        self.remote = remote
        self.__packet: bytearray = bytearray()

    def make_packet(self):
        self.__packet = bytearray()
        self.__packet += ((self.SYN << 7) + (self.ACK << 6) + (self.FIN << 5) + (self.RST << 4) +
                          (self.SAK << 3) + self._).to_bytes(1, 'big')
        self.__packet += struct.pack('!2I2H', self.SEQ, self.SEQ_ACK, self.LEN, 0)  # CHECKSUM
        extra = (4 - self.LEN % 4) % 4
        self.PAYLOAD_REAL = self.PAYLOAD + b'\x00' * extra
        self.CHECKSUM = self._checksum()

        self.__packet[-2:] = struct.pack('!H', self.CHECKSUM)
        self.__packet += self.PAYLOAD_REAL
        return self.__packet

    @staticmethod
    def resolve(bs: bytearray, addr: (str, int)) -> 'RDTPacket':
        r: RDTPacket = RDTPacket(remote=addr, SEQ=0, SEQ_ACK=0)
        bits, r.SEQ, r.SEQ_ACK, r.LEN, r.CHECKSUM = struct.unpack('!B2I2H', bs[:13])
        r.SYN, r.ACK, r.FIN, = (bits >> 7) & 1, (bits >> 6) & 1, (bits >> 5) & 1
        r.RST, r.SAK, r._ = (bits >> 4) & 1, (bits >> 3) & 1, bits & 0x7

        r.PAYLOAD_REAL = bs[13:]
        return r

    def _checksum(self) -> int:
        bs = self.PAYLOAD_REAL
        checksum = (self.SYN << 7 + self.ACK << 6 + self.FIN << 5 + self.RST << 4 + self.SAK << 3 + self._) << 24
        checksum += self.SEQ + self.SEQ_ACK + (self.LEN << 16)
        if len(bs) > 0:
            for i in range(0, len(bs), 4):
                checksum += (bs[i] << 24) + (bs[i + 1] << 16) + (bs[i + 2] << 8) + bs[i + 3]
        while checksum > 0xFFFF:
            checksum = (checksum % 0xFFFF) + (checksum // 0xFFFF)
        return checksum

    def check(self) -> bool:
        if len(self.PAYLOAD_REAL) % 4 != 0:
            return False
        check = self._checksum()
        self.PAYLOAD = self.PAYLOAD_REAL[:self.LEN]
        if check != self.CHECKSUM or self._ != 0:
            return False

        return True


class RDTSocket(UnreliableSocket):
    """
    The functions with which you are to build your RDT.
    -   recvfrom(bufsize)->bytes, addr
    -   sendto(bytes, address)
    -   bind(address)

    You can set the mode of the socket.
    -   settimeout(timeout)
    -   setblocking(flag)
    By default, a socket is created in the blocking mode. 
    https://docs.python.org/3/library/socket.html#socket-timeouts

    """

    def __init__(self, rate=None, debug=True):
        super().__init__(rate=rate)
        self._rate = rate
        self.addr = None
        self.debug = debug
        self.simple_sct = None
        self._event_loop = None
        self.is_close = False

    def accept(self) -> ('RDTSocket', (str, int)):
        """
        Accept a connection. The socket must be bound to an address and listening for 
        connections. The return value is a pair (conn, address) where conn is a new 
        socket object usable to send and receive data on the connection, and address 
        is the address bound to the socket on the other end of the connection.

        This function should be blocking. 
        """
        assert self.addr is not None, 'Not bound'
        if self._event_loop is None:
            self._event_loop = ServerEventLoop(self)
            self._event_loop.start()
            self.bind_(self.addr)
        assert isinstance(self._event_loop, ServerEventLoop), 'This socket is not a listener, please bind'
        while True:
            s: SimpleRDT = self._event_loop.accept()
            if s is not None:
                return s, s.remote
            time.sleep(0.001)

    def connect(self, address: (str, int)):
        """
        Connect to a remote socket at address.
        Corresponds to the process of establishing a connection on the client side.
        """
        assert not self._event_loop, 'Duplicated connecting or it is listening'
        self._event_loop = ClientEventLoop(self, address)
        self._event_loop.start()
        self._event_loop.put(RDTEventType.CONNECT, address)
        while True:
            s: SimpleRDT = self._event_loop.connect_()
            if s is not None:
                self.simple_sct = s
                return
            time.sleep(0.001)

    def recv(self, bufsize: int) -> bytes:
        """
        Receive data from the socket. 
        The return value is a bytes object representing the data received. 
        The maximum amount of data to be received at once is specified by bufsize. 
        
        Note that ONLY data send by the peer should be accepted.
        In other words, if someone else sends data to you from another address,
        it MUST NOT affect the data returned by this function.
        """
        assert self._event_loop and isinstance(self._event_loop, ClientEventLoop) and self.simple_sct, \
            "Connection not established or it is the listener"
        return self.simple_sct.recv(bufsize=bufsize)

    def send(self, _bytes: bytes):
        """
        Send data to the socket. 
        The socket must be connected to a remote socket, i.e. self._send_to must not be none.
        """
        assert self._event_loop and isinstance(self._event_loop, ClientEventLoop) and self.simple_sct, \
            "Connection not established yet."
        self.simple_sct.send(_bytes=_bytes)

    def close(self):
        """
        Finish the connection and release resources. For simplicity, assume that
        after a socket is closed, neither futher sends nor receives are allowed.
        """
        assert self._event_loop and not self.is_close, 'Duplicated closing'
        self.is_close = True
        self._event_loop.put(RDTEventType.LISTEN_CLOSE, None)

    def force_close(self):
        super(RDTSocket, self).close()

    def bind(self, address: (str, int)):
        assert self._event_loop is None, 'Can not duplicate binding'
        assert self.addr is None, 'Has bound'
        self.addr = address
        if self.debug:
            print('\033[0;33m122: bind-> ', address, '\033[0m')

    def bind_(self, address: (str, int)):
        super(RDTSocket, self).bind(address)

    def create_simple_socket(self, remote: (str, int), recv_offset: int, send_offset: int,
                             event_queue=None) -> 'SimpleRDT':
        if event_queue is not None:
            return SimpleRDT(self._rate, self.debug, recv_offset, send_offset, remote, event_queue)
        return SimpleRDT(self._rate, self.debug, recv_offset, send_offset, remote, self._event_loop.event_queue)

    def block_until_close(self):
        self._event_loop.join()

    def save_perf(self, path: str):
        """
        debug模式下保存RTT和Window变化的一个函数，只有client或者SimpleRDT可以用，server的listen不能用
        :param path:
        :return:
        """
        self.simple_sct.save_perf(path)


class SimpleRDT(RDTSocket):

    def __init__(self, rate, debug, recv_offset: int, send_offset: int, remote: (str, int), event_queue: SimpleQueue):
        super(SimpleRDT, self).__init__(rate, debug)
        self.remote: (str, int) = None  # 远方地址
        self.wait_ack = []  # 定时器数组，可能是已经触发的定时器，发出去的包等ack，无数据且不是(SYN, SYN_ACK, FIN)的包不会等待ACK，超时了会重发
        self.timeout_cnt = 0  # 连续超时计数
        self.wait_send = bytearray()  # 上层来的等待发送的数据
        self.wait_send_offset = 0  # 多次挪动wait_send很耗时，所以只移动指针，wait_send全发送后一次性清空
        self.wait_resend = []  # 等待窗口空闲进行重发的包
        self.SEQ = send_offset  # 下一个发包的SEQ
        self.ack_timer = RDTTimer(0, RDTEvent(RDTEventType.ACK_TIMEOUT, None))  # ACK等数据的计时器，超时就会发空ACK出去
        self.ack_timer.start_time = self.ack_timer.target_time = 0
        self.event_queue = event_queue  # 调度队列
        self.remote = remote  # 连接的对应的远端地址
        self.last_ACK = 0  # 自己发出去的最后一个ACK
        self.recv_buffer = []  # 收到的乱序包缓存
        self.SEQ_ACK = recv_offset  # 收到的最后一个正序SEQ
        self.data: bytearray = bytearray()  # 收好的正序数据
        self.status = None  # 这个连接当前的状态
        self.is_close = False  # 上层是否close
        self.remote_close = False  # 远方是否挥手完毕
        self.lock: threading.RLock = threading.RLock()  # 锁
        self.BASE_RTT = 0  # 基准应答延迟
        self.SEND_WINDOW_SIZE = 3  # 发送窗口大小，限制 wait_ack 的大小
        self.last_bomb = 0  # 上次强制降窗
        self.destroy_timer = None  # 强制销毁定时器
        self.perf = []  # 记录性能的数组，只在debug模式下开启

    @property
    def current_window(self):
        return len(self.wait_ack) - len(self.wait_resend)

    def close(self):
        assert not self.is_close, 'Duplicated close'
        self.is_close = True
        with self.lock:
            if self.remote_close:
                return
        self.event_queue.put(RDTEvent(RDTEventType.SIMPLE_CLOSE, self.remote))

    def send(self, _bytes: bytes):
        assert not self.is_close and not self.remote_close, 'Closed!'
        self.event_queue.put(RDTEvent(RDTEventType.SEND, (self.remote, _bytes)))

    def recv(self, bufsize: int) -> bytes:
        assert not self.is_close, 'Closed!'
        while True:
            with self.lock:
                if len(self.data) > 0:
                    re = self.data[:bufsize]
                    self.data = self.data[bufsize:]
                    return re
                if self.remote_close:
                    return b''
            time.sleep(0.0001)

    def connect(self, address: (str, int)):
        assert False, 'Duplicated connecting'

    def accept(self) -> ('RDTSocket', (str, int)):
        assert False, 'This can not listen'

    def deal_RTT(self, RTT: float):
        assert RTT >= 0, 'RTT-> %d ?' % RTT
        if self.debug:
            print('\033[0;34m212: 更新前WINDOW-> ', self.SEND_WINDOW_SIZE, 'RTT->', RTT)
        if self.BASE_RTT == 0:
            self.BASE_RTT = RTT
        tr_differ = (1 - (self.BASE_RTT / RTT) ** 3) * self.SEND_WINDOW_SIZE
        if self.debug:
            print('217: 计算出的differ-> ', tr_differ)
        if tr_differ > DECREASE_:
            self.SEND_WINDOW_SIZE -= min(0.8, log(self.SEND_WINDOW_SIZE) / max(self.SEND_WINDOW_SIZE / 3, 1))
        elif tr_differ < INCREASE_:
            self.SEND_WINDOW_SIZE += 1 / max(1.0, log(self.SEND_WINDOW_SIZE))
        else:
            self.SEND_WINDOW_SIZE += log(self.SEND_WINDOW_SIZE + 1) / self.SEND_WINDOW_SIZE
        self.BASE_RTT = self.BASE_RTT * RTT_ + (1 - RTT_) * RTT
        if self.debug:
            print('226: 更新后WINDOW->', self.SEND_WINDOW_SIZE, '\033[0m')
            self.perf.append({
                'BASE-RTT': self.BASE_RTT,
                'RTT': RTT,
                'WINDOW': self.SEND_WINDOW_SIZE
            })

    def deal_recv_data(self, pkt: RDTPacket) -> (bool, int):
        if pkt.SEQ == self.SEQ_ACK:
            with self.lock:
                self.data.extend(pkt.PAYLOAD)  # 放进对应连接的接受数据里
            self.SEQ_ACK += pkt.LEN
            while len(self.recv_buffer) > 0 and self.recv_buffer[0].SEQ == self.SEQ_ACK:
                pkt = self.recv_buffer.pop(0)
                with self.lock:
                    self.data.extend(pkt.PAYLOAD)
                self.SEQ_ACK += pkt.LEN
            return True, 0
        elif pkt.SEQ > self.SEQ_ACK:
            index = 0
            while len(self.recv_buffer) > index:
                if self.recv_buffer[index].SEQ < pkt.SEQ:
                    index += 1
                elif self.recv_buffer[index].SEQ == pkt.SEQ:
                    return False, pkt.SEQ
                else:
                    self.recv_buffer.insert(index, pkt)
                    return False, pkt.SEQ
            self.recv_buffer.append(pkt)
            return False, pkt.SEQ
        else:
            return False, 0

    def save_perf(self, path: str):
        with open(path, 'w') as f:
            json.dump(self.perf, f)


class EventLoop(threading.Thread):
    def __init__(self, _socket: RDTSocket):
        super().__init__()
        self.socket: RDTSocket = _socket
        self.event_queue: SimpleQueue = SimpleQueue()
        self.send_loop: SendLoop = SendLoop(_socket, self)
        self.recv_loop: RecvLoop = RecvLoop(_socket, self)
        self.timers = []

    def run(self) -> None:
        if self.socket.debug:
            print('\033[0;36m\n275: Event loop start->', self.getName(), ' \033[0m')
        while True:
            while len(self.timers) > 0 and self.timers[0].target_time <= time.time():
                timer = self.timers.pop(0)
                self.event_queue.put_nowait(timer.event)
                if self.socket.debug:
                    print('\033[0;37m281: Timer-> ', timer.target_time - timer.start_time, 's | ', timer.event.type,
                          '\033[0m')
            if self.event_queue.empty():
                time.sleep(0.00001)
            else:
                try:
                    event: RDTEvent = self.event_queue.get_nowait()
                    if self.socket.debug:
                        print('\033[0;37m290: Event-> ', event.type, '\033[0m')
                    if event.type == RDTEventType.VANISH:
                        if len(self.timers) > 0:
                            time.sleep(self.timers[0].target_time - time.time())
                            self.put(RDTEventType.VANISH, None)
                            continue
                        self.close()
                        self.before_vanish()
                        break
                    elif event.type == RDTEventType.DESTROY_ALL:
                        self.on_destroy_all()
                    elif event.type == RDTEventType.LISTEN_CLOSE:
                        self.on_listen_close()
                    elif event.type == RDTEventType.SIMPLE_CLOSE:
                        self.on_simple_close(event.body)
                    elif event.type == RDTEventType.DESTROY_SIMPLE:
                        self.on_destroy_simple(event.body)
                    elif event.type == RDTEventType.SEND_ACK:
                        self.on_send_ack(event.body)
                    elif event.type == RDTEventType.SEND_FIN:
                        self.on_send_fin(event.body)
                    elif event.type == RDTEventType.SAK:
                        self.on_sak(event.body)
                    elif event.type == RDTEventType.SEND:
                        self.on_send(event.body)
                    elif event.type == RDTEventType.CONNECT:
                        self.on_connect(event.body)
                    elif event.type == RDTEventType.CORRUPTION:
                        self.on_corruption(event.body)
                    elif event.type == RDTEventType.ACK_TIMEOUT:
                        self.on_ack_timeout(event.body)
                    elif event.type == RDTEventType.RST:
                        self.on_rst(event.body)
                    elif event.type == RDTEventType.UNKNOWN_ERROR:
                        self.on_unknown_error(event.body)
                    elif event.type == RDTEventType.FIN_ACK:
                        self.on_fin_ack(event.body)
                    elif event.type == RDTEventType.FIN:
                        self.on_fin(event.body)
                    elif event.type == RDTEventType.ACK:
                        self.on_ack(event.body)
                    elif event.type == RDTEventType.SYN_ACK:
                        self.on_syn_ack(event.body)
                    elif event.type == RDTEventType.SYN:
                        self.on_syn(event.body)
                    else:
                        self.on_sb()
                except Empty:
                    pass
                except AssertionError as ev:
                    if self.socket.debug:
                        print('\033[0;31m342: Assertion->', ev, '\033[0m')
                except Exception as error:
                    print('\033[0;31m345: Error->', error, '\033[0m')

    def close(self):
        self.send_loop.put(0)
        self.recv_loop.event_queue.put(0)
        self.send_loop.join()
        self.socket.force_close()
        self.recv_loop.join()

    def put(self, e_type: RDTEventType, e_args):
        self.event_queue.put(RDTEvent(e_type, e_args))

    def get_nowait(self) -> RDTEvent:
        return self.event_queue.get_nowait()

    def on_sb(self):
        assert False, '!#$%^&*()_+|}{":?;><~`./[,]-=\\\''  # ???

    def on_connect(self, remote: (str, int)):
        pass  # 主动握手

    def on_corruption(self, pkt: RDTPacket):
        if self.socket.debug:
            print('\033[0;31m367: Corruption-> SEQ=', pkt.SEQ, '\033[0m')
        pass  # 包炸了

    def on_ack_timeout(self, pkt: RDTPacket):
        pass  # 等ACK超时了

    def on_rst(self, pkt: RDTPacket):
        pass  # remote 拒绝了

    def on_unknown_error(self, error: Exception):
        if self.socket.debug:
            print('\033[0;31m378: Unknown error-> ', error, '\033[0m')
        pass  # send loop 或 recv loop 报错了

    def on_fin_ack(self, pkt: RDTPacket):
        pass  # remote 挥手成功

    def on_fin(self, pkt: RDTPacket):
        pass  # remote 试图挥手

    def on_ack(self, pkt: RDTPacket):
        pass  # 正常收包

    def on_syn(self, pkt: RDTPacket):
        pass  # 有 remote 来SYN了

    def on_syn_ack(self, pkt: RDTPacket):
        pass  # 对方接受握手

    def on_send(self, body: ((str, int), bytes)):
        pass  # 上层调用send

    def on_sak(self, pkt: RDTPacket):
        pass  # 收了个SAK包

    def on_send_fin(self, skt: SimpleRDT):
        """
        尝试发送fin包，如果仍有数据发送或等待接收，则使用计时器再次尝试
        :param skt:
        :return: void
        """

    def on_send_ack(self, simple_skt: SimpleRDT):
        pass  # 延时到了，判断是否发送ack

    def on_simple_close(self, remote: (str, int)):
        pass  # 单连接调用close

    def on_destroy_simple(self, skt: SimpleRDT):
        pass  # 简单连接的destroy

    def on_listen_close(self):
        pass  # 对管理监听的socket调用了close，这个方法在两个不同的事件循环中是完全不一样的

    def on_destroy_all(self):
        pass  # 尝试销毁循环线程

    def before_vanish(self):
        pass  # 事件循环消失前最后的挣扎

    def push_timer(self, timeout: float, ev: RDTEvent):
        index = 0
        timer = RDTTimer(timeout=timeout, e=ev)
        while len(self.timers) > index:
            if self.timers[index].target_time <= timer.target_time:
                index += 1
            else:
                self.timers.insert(index, timer)
                return timer
        self.timers.append(timer)
        return timer

    def push_raw_timer(self, timer: RDTTimer):
        self.timers.append(timer)

    def cancel_timer(self, _: RDTTimer):
        try:
            self.timers.remove(_)
        except Exception as ev:
            if self.socket.debug:
                print('\033[0;33m440: Exception->', ev, '\033[0m')

    def send_sak_pkt(self, seq_sak: int, sct: SimpleRDT):
        sak_pkt = RDTPacket(SAK=1, SEQ=seq_sak, remote=sct.remote, SEQ_ACK=sct.SEQ_ACK)
        self.send_loop.put(sak_pkt)

    def await_send_ack(self, skt: SimpleRDT):
        timeout = SEND_WAIT
        if skt.ack_timer and time.time() < skt.ack_timer.target_time:
            return
        _ = self.push_timer(timeout, RDTEvent(RDTEventType.SEND_ACK, skt))
        skt.ack_timer = _

    def await_send_fin(self, skt: SimpleRDT):
        self.push_timer(SEND_FIN_WAIT, RDTEvent(RDTEventType.SEND_FIN, skt))

    def await_destroy_all(self):
        self.push_timer(1, RDTEvent(RDTEventType.DESTROY_ALL, None))

    def call_send(self, skt: SimpleRDT):
        self.put(RDTEventType.SEND, (skt.remote, bytes()))

    def deal_ack(self, simple_sct: SimpleRDT, pkt: RDTPacket):
        if simple_sct.debug:
            print('\033[0;36m471: pkt SEQ ->', pkt.SEQ, 'pkt SEQ_ACK ->', pkt.SEQ_ACK, '当前 SEQ_ACK->',
                  simple_sct.SEQ_ACK, '当前 SEQ->', simple_sct.SEQ)
        # 处理 ACK
        self.pop_wait_ack(simple_sct, pkt)
        # 窗口可能空了，去发数据
        self.call_send(simple_sct)
        # 处理数据
        if pkt.LEN == 0:
            return
        ACK, SEQ_SAK = simple_sct.deal_recv_data(pkt)
        if ACK:
            if simple_sct.debug:
                print('\033[0;32m483: '
                      'ACK-> SEQ_ACK=', simple_sct.SEQ_ACK, '待收data 长度->', len(simple_sct.data),
                      '\033[0m')
            self.await_send_ack(simple_sct)
        elif SEQ_SAK != 0:
            if simple_sct.debug:
                print('\033[0;34m482: SAK-> SEQ_SAK=', pkt.SEQ, '\033[0m')
            self.send_sak_pkt(SEQ_SAK, simple_sct)
        else:
            self.send_ack_pkt(simple_sct)
            if simple_sct.debug:
                print('\033[0;33m494: 无效包-> SEQ=', pkt.SEQ, ' 当前SEQ=', simple_sct.SEQ_ACK, '\033[0m')

    def deal_sak(self, simple_sct: SimpleRDT, pkt: RDTPacket):
        SEQ_SAK = pkt.SEQ
        if self.socket.debug:
            print('\033[0;33m499: SAK->', SEQ_SAK)
        timer = None
        for t in simple_sct.wait_ack:
            if t.event.body.SEQ == SEQ_SAK:
                timer = t
                break
        assert timer is not None, 'Timer dose not exist'
        RTT = time.time() - timer.start_time
        simple_sct.deal_RTT(RTT)
        simple_sct.wait_ack.remove(timer)
        if timer.active:
            self.cancel_timer(timer)
        else:
            simple_sct.wait_resend.remove(timer)

        self.pop_wait_ack(simple_sct, pkt)
        # 尝试发数据
        self.call_send(simple_sct)

    def pop_wait_ack(self, simple_sct, pkt):
        while len(simple_sct.wait_ack) > 0:
            timer: RDTTimer = simple_sct.wait_ack[0]
            wait_ack_pkt: RDTPacket = timer.event.body
            if wait_ack_pkt.SEQ + wait_ack_pkt.LEN < pkt.SEQ_ACK:
                if not timer.active:
                    simple_sct.wait_resend.remove(timer)
                self.cancel_timer(simple_sct.wait_ack.pop(0))
            elif wait_ack_pkt.SEQ + wait_ack_pkt.LEN == pkt.SEQ_ACK:
                if not timer.active:
                    simple_sct.wait_resend.remove(timer)
                self.cancel_timer(simple_sct.wait_ack.pop(0))
                if timer.event.body.FIN == 1:
                    self.put(RDTEventType.DESTROY_SIMPLE, simple_sct)
                RTT = time.time() - timer.start_time
                simple_sct.deal_RTT(RTT)
                break
            else:
                break

    def deal_resend(self, simple_sct: SimpleRDT):
        while simple_sct.current_window + 1 < simple_sct.SEND_WINDOW_SIZE and len(simple_sct.wait_resend) > 0:
            timer: RDTTimer = simple_sct.wait_resend.pop(0)
            timer.start_time = time.time()
            timer.target_time = timer.start_time + simple_sct.BASE_RTT * 2 + EXTRA_ACK_WAIT
            timer.active = True
            if simple_sct.debug:
                print('\033[0;33m545: 重发包, SEQ=', timer.event.body.SEQ, '当前占用->', simple_sct.current_window,
                      '窗口-> ', simple_sct.SEND_WINDOW_SIZE, '当前等待重发->', len(simple_sct.wait_resend), ' RTT-> ',
                      simple_sct.BASE_RTT, '\033[0m')
            self.push_raw_timer(timer)
            self.send_loop.put(timer.event.body)

    def deal_send(self, simple_sct: SimpleRDT, bs: bytes):
        simple_sct.wait_send.extend(bs)
        self.deal_resend(simple_sct)
        while simple_sct.current_window < simple_sct.SEND_WINDOW_SIZE:
            if len(simple_sct.wait_send) == 0 or simple_sct.wait_send_offset >= len(simple_sct.wait_send):
                break
            pkt = RDTPacket(remote=simple_sct.remote, ACK=1, SEQ=simple_sct.SEQ, SEQ_ACK=simple_sct.SEQ_ACK,
                            PAYLOAD=simple_sct.wait_send[
                                    simple_sct.wait_send_offset:simple_sct.wait_send_offset + MAX_PKT_LEN])
            self.send_loop.put(pkt)
            simple_sct.SEQ += pkt.LEN
            simple_sct.last_ACK = simple_sct.SEQ_ACK
            simple_sct.wait_send_offset += MAX_PKT_LEN
            if simple_sct.wait_send_offset >= len(simple_sct.wait_send):
                simple_sct.wait_send.clear()
                simple_sct.wait_send_offset = 0
            if self.socket.debug:
                print('\033[0;33m568: 发送包 SEQ->', pkt.SEQ)
            timer = self.push_timer(simple_sct.BASE_RTT * 2 + EXTRA_ACK_WAIT, RDTEvent(RDTEventType.ACK_TIMEOUT, pkt))
            simple_sct.wait_ack.append(timer)
        if simple_sct.debug:
            print('\033[0;36m572: 当前等待发送数据长度->', len(simple_sct.wait_send) - simple_sct.wait_send_offset)

    def deal_ack_timeout(self, simple_sct: SimpleRDT, pkt: RDTPacket):
        timer = None
        index = 0
        for i in range(len(simple_sct.wait_ack)):
            _timer: RDTTimer = simple_sct.wait_ack[i]
            if _timer.event.body is pkt:
                timer = _timer
                index = i
                break
        assert timer is not None, 'Can not find timer'
        pkt.SEQ_ACK = simple_sct.SEQ_ACK
        simple_sct.last_ACK = simple_sct.SEQ_ACK
        if simple_sct.SEND_WINDOW_SIZE > 1.6 and index / simple_sct.SEND_WINDOW_SIZE > BOMB_RATE \
                and time.time() - simple_sct.last_bomb > 2 * simple_sct.BASE_RTT + EXTRA_ACK_WAIT:  # 连续丢包强制降窗
            simple_sct.SEND_WINDOW_SIZE = simple_sct.SEND_WINDOW_SIZE * 0.65
            simple_sct.last_bomb = time.time()
            if simple_sct.debug:
                print('\033[0;33m583: 丢包降窗->', simple_sct.SEND_WINDOW_SIZE)
        timer.active = False  # 定时器记为无效
        simple_sct.wait_resend.append(timer)
        self.deal_resend(simple_sct)

    def send_ack_pkt(self, simple_sct):
        pkt: RDTPacket = RDTPacket(remote=simple_sct.remote, ACK=1, SEQ=simple_sct.SEQ, SEQ_ACK=simple_sct.SEQ_ACK)
        simple_sct.last_ACK = simple_sct.SEQ_ACK
        self.send_loop.put(pkt)

    def send_fin_ack_pkt(self, simple_sct: SimpleRDT):
        pkt: RDTPacket = RDTPacket(remote=simple_sct.remote, FIN=1, ACK=1, SEQ=simple_sct.SEQ,
                                   SEQ_ACK=simple_sct.SEQ_ACK)
        self.send_loop.put(pkt)

    def deal_send_fin(self, skt: SimpleRDT):
        pkt = RDTPacket(remote=skt.remote, FIN=1, SEQ=skt.SEQ, SEQ_ACK=skt.SEQ_ACK, PAYLOAD=bytes(1))
        skt.SEQ += 1  # 强制加一做区分
        for i in range(3):
            self.send_loop.put(pkt)
        if skt.debug:
            print('\033[0;34m612: 发送FIN， 当前状态-> ', skt.status, '\033[0m')
        if skt.status != RDTConnectionStatus.FIN_:
            skt.status = RDTConnectionStatus.FIN
            timer = self.push_timer(skt.BASE_RTT + EXTRA_ACK_WAIT, RDTEvent(RDTEventType.ACK_TIMEOUT, pkt))
            skt.wait_ack.append(timer)
            skt.destroy_timer = self.push_timer(skt.BASE_RTT * 16 + EXTRA_ACK_WAIT * 8,
                                                RDTEvent(RDTEventType.DESTROY_SIMPLE, skt))
        else:
            self.push_timer(skt.BASE_RTT * 2 + EXTRA_ACK_WAIT, RDTEvent(RDTEventType.DESTROY_SIMPLE, skt))


class ServerEventLoop(EventLoop):
    def __init__(self, listen_socket: RDTSocket):
        super().__init__(listen_socket)
        self.connections: dict = {}
        self.accept_queue = SimpleQueue()
        self.__is_close = False
        self.setName('ServerEventLoop')

    def run(self) -> None:
        self.send_loop.start()
        self.recv_loop.start()
        super(ServerEventLoop, self).run()

    def accept(self) -> (RDTSocket, (str, int)):
        assert not self.__is_close, 'Can not accept after close'
        if not self.accept_queue.empty():
            try:
                return self.accept_queue.get_nowait()
            except Empty as ev:
                print('\033[0;31m642: Empty-> ', ev, '\033[0m')

    def on_syn(self, pkt: RDTPacket):
        remote = pkt.remote
        if remote in self.connections:
            simple_sct = self.connections[remote]
            simple_sct.SEQ_ACK = max(simple_sct.SEQ_ACK, pkt.SEQ + pkt.LEN)
            syn_ack_pkt = RDTPacket(SYN=1, ACK=1, remote=remote, SEQ=simple_sct.SEQ, SEQ_ACK=simple_sct.SEQ_ACK)
            self.send_loop.put(syn_ack_pkt)
            return
        elif self.__is_close:
            self.send_loop.put(RDTPacket(remote=pkt.remote, SEQ=0, SEQ_ACK=0, RST=1))
            return
        assert remote not in self.connections, 'Has SYN'
        simple_sct = self.socket.create_simple_socket(remote, pkt.SEQ, pkt.SEQ_ACK)
        simple_sct.SEQ_ACK += pkt.LEN
        simple_sct.status = RDTConnectionStatus.SYN_
        self.connections[remote] = simple_sct
        syn_ack_pkt = RDTPacket(SYN=1, ACK=1, remote=remote, SEQ=simple_sct.SEQ, SEQ_ACK=simple_sct.SEQ_ACK,
                                PAYLOAD=bytes(1024))
        simple_sct.SEQ += 1024
        self.send_loop.put(syn_ack_pkt)
        timer = self.push_timer(SYN_ACK_WAIT,
                                RDTEvent(RDTEventType.ACK_TIMEOUT, syn_ack_pkt))
        simple_sct.wait_ack.append(timer)
        if self.socket.debug:
            print('\033[0;32m668: SYN<- ', remote, '\033[0m')

    def on_syn_ack(self, pkt: RDTPacket):
        assert False, 'SYN_ACK ???'

    def on_ack(self, pkt: RDTPacket):
        simple_sct = self.get_simple_sct(pkt)
        if simple_sct.status == RDTConnectionStatus.SYN_:
            self.accept_queue.put(simple_sct)
            simple_sct.status = RDTConnectionStatus.ACK_

        self.deal_ack(simple_sct=simple_sct, pkt=pkt)

    def on_fin(self, pkt: RDTPacket):
        if pkt.remote not in self.connections:
            self.send_loop.put(RDTPacket(remote=pkt.remote, FIN=1, ACK=1, SEQ=0, SEQ_ACK=0))
            return
        simple_sct: SimpleRDT = self.get_simple_sct(pkt)
        simple_sct.SEQ_ACK = pkt.SEQ + pkt.LEN
        if simple_sct.status.value < RDTConnectionStatus.FIN.value:
            simple_sct.status = RDTConnectionStatus.FIN_
            if simple_sct.debug:
                print('\033[0;33m690: FIN<- ', pkt.remote, '\033[0m')
            self.await_send_fin(simple_sct)
        elif simple_sct.status == RDTConnectionStatus.FIN:
            if simple_sct.debug:
                print('\033[0;33m695: FIN success', pkt.remote, '\033[0m')
            self.cancel_timer(simple_sct.destroy_timer)
            self.send_fin_ack_pkt(simple_sct)
            self.put(RDTEventType.DESTROY_SIMPLE, simple_sct)

    def on_fin_ack(self, pkt: RDTPacket):
        simple_sct: SimpleRDT = self.get_simple_sct(pkt)
        self.cancel_timer(simple_sct.destroy_timer)
        if simple_sct.status.value < RDTConnectionStatus.FIN_ACK_.value:
            simple_sct.status = RDTConnectionStatus.FIN_ACK_
        else:
            return  # FIN ACK过了
        self.put(RDTEventType.DESTROY_SIMPLE, simple_sct)

    def on_send(self, r: ((str, int), bytes)):
        remote, bs = r
        simple_sct: SimpleRDT = self.connections[remote]
        assert simple_sct.status == RDTConnectionStatus.ACK_, 'Send with a wrong state'
        self.deal_send(simple_sct, bs)

    def on_send_ack(self, simple_sct: SimpleRDT):
        if simple_sct.last_ACK == simple_sct.SEQ_ACK and simple_sct.status == RDTConnectionStatus.ACK_:
            return  # ACK过了
        self.send_ack_pkt(simple_sct)

    def on_send_fin(self, skt: SimpleRDT):
        if len(skt.wait_ack) > 0 or len(skt.wait_send) > 0:
            self.await_send_fin(skt)
            return
        self.deal_send_fin(skt)

    def on_connect(self, remote: (str, int)):
        assert False, 'connect ???'

    def on_rst(self, pkt: RDTPacket):
        assert False, 'RST ???'

    def on_ack_timeout(self, pkt: RDTPacket):
        simple_sct: SimpleRDT = self.get_simple_sct(pkt)
        self.deal_ack_timeout(simple_sct, pkt)

    def on_sak(self, pkt: RDTPacket):
        self.deal_sak(self.get_simple_sct(pkt), pkt)

    def get_simple_sct(self, pkt: RDTPacket):
        try:
            assert pkt.remote in self.connections, 'No such connection'
        except AssertionError:
            self.send_loop.put(RDTPacket(remote=pkt.remote, SEQ=0, SEQ_ACK=0, RST=1))
        return self.connections[pkt.remote]

    def on_simple_close(self, remote: (str, int)):
        assert remote in self.connections, 'No such connection'
        simple_sct: SimpleRDT = self.connections[remote]
        if simple_sct.status.value >= RDTConnectionStatus.FIN.value:
            self.put(RDTEventType.DESTROY_SIMPLE, simple_sct)
        else:
            self.put(RDTEventType.SEND_FIN, simple_sct)

    def on_listen_close(self):
        assert not self.__is_close, 'Has closed'
        self.__is_close = True
        while not self.accept_queue.empty():
            _, remote = self.accept_queue.get()
            del self.connections[remote]
        self.put(RDTEventType.DESTROY_ALL, None)

    def on_destroy_simple(self, skt: SimpleRDT):
        assert skt.remote in self.connections, 'No such connection'
        with skt.lock:
            skt.remote_close = True
        for t in self.connections[skt.remote].wait_ack:
            self.cancel_timer(t)
        del self.connections[skt.remote]

    def on_destroy_all(self):
        if len(self.connections) == 0:
            self.put(RDTEventType.VANISH, None)
            if self.socket.debug:
                print('\033[0;31m774:完全销毁 DESTROY_ALL -> VANISH')
        else:
            self.await_destroy_all()


class ClientEventLoop(EventLoop):
    def __init__(self, socket_: RDTSocket, remote: (str, int)):
        super().__init__(socket_)
        self.simple_sct: SimpleRDT = socket_.create_simple_socket(remote, random.randint(0, 1000000),
                                                                  random.randint(0, 1000000), self.event_queue)
        self.setName('ClientEventLoop')

    def run(self) -> None:
        super(ClientEventLoop, self).run()

    def on_syn(self, pkt: RDTPacket):
        assert False, 'SYN ???'

    def on_syn_ack(self, pkt: RDTPacket):
        assert pkt.remote == self.simple_sct.remote
        self.simple_sct.SEQ_ACK = max(self.simple_sct.SEQ_ACK, pkt.SEQ + pkt.LEN)
        self.send_ack_pkt(self.simple_sct)
        if self.simple_sct.status is None:
            self.simple_sct.status = RDTConnectionStatus.SYN_ACK_
            return
        if self.simple_sct.wait_ack[0].event.body.SYN == 1:
            self.cancel_timer(self.simple_sct.wait_ack.pop(0))

    def on_ack(self, pkt: RDTPacket):
        assert pkt.remote == self.simple_sct.remote
        if self.simple_sct.status == RDTConnectionStatus.SYN_ACK_:
            self.simple_sct.status = RDTConnectionStatus.ACK_
        self.deal_ack(simple_sct=self.simple_sct, pkt=pkt)

    def on_fin(self, pkt: RDTPacket):
        assert pkt.remote == self.simple_sct.remote
        self.simple_sct.SEQ_ACK = pkt.SEQ + pkt.LEN
        if self.simple_sct.status.value < RDTConnectionStatus.FIN.value:
            self.simple_sct.status = RDTConnectionStatus.FIN_
            self.await_send_fin(self.simple_sct)
        elif self.simple_sct.status == RDTConnectionStatus.FIN:
            self.cancel_timer(self.simple_sct.destroy_timer)
            self.send_fin_ack_pkt(self.simple_sct)
            self.put(RDTEventType.DESTROY_ALL, None)

    def on_fin_ack(self, pkt: RDTPacket):
        assert pkt.remote == self.simple_sct.remote
        self.cancel_timer(self.simple_sct.destroy_timer)
        if self.simple_sct.debug:
            print('\033[0;32m824: FIN_ACK 状态-> ', self.simple_sct.status, '\033[0m')
        if self.simple_sct.status.value < RDTConnectionStatus.FIN_ACK_.value:
            self.simple_sct.status = RDTConnectionStatus.FIN_ACK_
        self.put(RDTEventType.DESTROY_ALL, None)

    def on_send(self, body: ((str, int), bytes)):
        self.deal_send(self.simple_sct, body[1])

    def on_send_ack(self, simple_skt: SimpleRDT):
        if self.simple_sct.last_ACK == self.simple_sct.SEQ_ACK and self.simple_sct.status != RDTConnectionStatus.ACK_:
            return  # ACK过了
        self.send_ack_pkt(self.simple_sct)

    def on_send_fin(self, skt: SimpleRDT):
        if len(skt.wait_ack) > 0 or len(skt.wait_send) > 0:
            self.await_send_fin(skt)
            return
        self.deal_send_fin(skt)

    def on_connect(self, remote: (str, int)):
        if self.socket.addr is not None:
            self.socket.bind_(self.socket.addr)
        else:
            addr = ('127.0.0.1', random.randint(1024, 65535))
            while True:
                try:
                    self.socket.bind_(addr)
                    addr = ('127.0.0.1', random.randint(1024, 65535))
                    break
                except Exception as ev:
                    if self.socket.debug:
                        print('\033[0;31m855: Try ', addr, ' Fail-> ', ev, '\033[0m')
        self.send_loop.start()
        self.recv_loop.start()
        pkt: RDTPacket = RDTPacket(remote=remote, SYN=1, SEQ=self.simple_sct.SEQ, SEQ_ACK=self.simple_sct.SEQ_ACK,
                                   PAYLOAD=bytes(1024))
        self.simple_sct.SEQ += 1024
        self.send_loop.put(pkt)
        if self.simple_sct.debug:
            print('\033[0;32m863: Try connect-> ', remote, '\033[0m')
        timer = self.push_timer(SYN_ACK_WAIT, RDTEvent(RDTEventType.ACK_TIMEOUT, pkt))
        self.simple_sct.wait_ack.append(timer)

    def on_rst(self, pkt: RDTPacket):
        self.on_destroy_all()  # 强制销毁
        assert False, 'RST ???'

    def on_ack_timeout(self, pkt: RDTPacket):
        self.deal_ack_timeout(self.simple_sct, pkt)

    def on_sak(self, pkt: RDTPacket):
        assert pkt.remote == self.simple_sct.remote
        self.deal_sak(self.simple_sct, pkt)

    def on_simple_close(self, remote: (str, int)):
        assert False, 'SimpleRDT close ???'

    def on_listen_close(self):
        self.put(RDTEventType.SEND_FIN, self.simple_sct)

    def on_destroy_simple(self, skt: SimpleRDT):
        self.on_destroy_all()

    def on_destroy_all(self):
        for timer in self.simple_sct.wait_ack:
            self.cancel_timer(timer)
        with self.simple_sct.lock:
            self.simple_sct.remote_close = True
        self.put(RDTEventType.VANISH, None)

    def connect_(self):
        if self.simple_sct.status is None:
            return None
        elif self.simple_sct.status.value >= RDTConnectionStatus.SYN_ACK_.value:
            return self.simple_sct
        return None

    def on_sb(self):
        super(ClientEventLoop, self).on_sb()


class SendLoop(threading.Thread):
    def __init__(self, rdt_socket: RDTSocket, event_loop: EventLoop):
        super().__init__()
        self.socket: RDTSocket = rdt_socket
        self.send_queue: SimpleQueue = SimpleQueue()
        self.event_loop = event_loop

    def run(self) -> None:
        if self.socket.debug:
            print('\033[0;32mSend loop start\033[0m')
        while True:
            try:
                if not self.send_queue.empty():
                    try:
                        pkt: RDTPacket = self.send_queue.get_nowait()
                        if pkt == 0:
                            break
                        _bytes = pkt.make_packet()
                        self.socket.sendto(_bytes, pkt.remote)
                    except Empty:
                        pass
                else:
                    time.sleep(0.00001)
            except AssertionError as a:
                print('\033[0;31m', a, '\033[0m')

    def put(self, ev):
        self.send_queue.put(ev)


class RecvLoop(threading.Thread):
    def __init__(self, rdt_socket: RDTSocket, event_loop: EventLoop):
        super().__init__()
        self.socket: RDTSocket = rdt_socket
        self.event_queue = SimpleQueue()
        self.event_loop = event_loop

    def run(self) -> None:
        if self.socket.debug:
            print('\033[0;32mRecv loop start\033[0m')
        while self.event_queue.empty():
            try:
                rec, addr = self.socket.recvfrom(MAX_PKT_LEN + 13 + 8)
                pkt = RDTPacket.resolve(rec, addr)
                if pkt.check():
                    if pkt.SYN == 1:
                        if pkt.ACK == 0:
                            self.event_loop.put(RDTEventType.SYN, pkt)
                        else:
                            self.event_loop.put(RDTEventType.SYN_ACK, pkt)
                    elif pkt.FIN == 1:
                        if pkt.ACK == 0:
                            self.event_loop.put(RDTEventType.FIN, pkt)
                        else:
                            self.event_loop.put(RDTEventType.FIN_ACK, pkt)
                    elif pkt.RST == 1:
                        self.event_loop.put(RDTEventType.RST, pkt)
                    elif pkt.ACK == 1:
                        self.event_loop.put(RDTEventType.ACK, pkt)
                    elif pkt.SAK == 1:
                        self.event_loop.put(RDTEventType.SAK, pkt)
                    else:
                        self.event_loop.put(RDTEventType.CORRUPTION, pkt)
                else:
                    self.event_loop.put(RDTEventType.CORRUPTION, pkt)
            except AssertionError as a:
                print('\033[0;31m', a, '\033[0m')
            except Exception as ev:
                self.event_loop.put(RDTEventType.UNKNOWN_ERROR, ev)


"""
You can define additional functions and classes to do thing such as packing/unpacking packets, or threading.

"""
