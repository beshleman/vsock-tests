#!/usr/bin/python3

import argparse
import socket
import sys
import signal
import sys
from threading import Timer, Event
from timeit import default_timer as timer

t = None
total = 0
start = None
done = Event()

class Size:
    KB = 1 << 10
    MB = 1 << 20
    GB = 1 << 30
    TB = 1 << 40

    @staticmethod
    def human_readable(byte_count):
        rounded_str = lambda x: str(round(x, 2))

        if byte_count >= Size.TB:
            return rounded_str(byte_count / Size.TB) + "TB"
        if byte_count >= Size.GB:
            return rounded_str(byte_count / Size.GB) + "GB"
        if byte_count >= Size.MB:
            return rounded_str(byte_count / Size.MB) + "MB"
        if byte_count >= Size.KB:
            return rounded_str(byte_count / Size.KB) + "KB"
        return rounded_str(byte_count) + "B"

def signal_handler(sig, frame):
    done.set()
    if start:
        end = timer()
        elp = end - start
        print("time ", end - start)
        print("speed", total / elp / 1024 / 1024, 'MB/s' )
    print("total bytes", Size.human_readable(total))
    exit(0)

def get_socktype(s):
    return {
        "stream": socket.SOCK_STREAM,
        "dgram": socket.SOCK_DGRAM,
        "seqpacket": socket.SOCK_SEQPACKET,
    }.get(s)

def start_monitor():
    global t

    if t:
        t.cancel()


    print("data received={}".format(Size.human_readable(total)))

    if not done.is_set():
        t = Timer(3, start_monitor)
        t.start()

def getfamily(args):
    return socket.AF_INET if args.inet else socket.AF_VSOCK

def getaddress(args):
    if args.inet:
        return '0.0.0.0', args.port
    return socket.VMADDR_CID_HOST, args.port

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("socktype", choices=["stream", "dgram", "seqpacket"])
    parser.add_argument("port", type=int)
    parser.add_argument("--inet", "-i", action="store_true", help="Use AF_INET (tcp or udp) instead of vsock")
    parser.add_argument("--recv", "-r", action="store_true", help="Recieve and print a message")
    args = parser.parse_args()

    if args.inet:
        recv_size = 128 * 1024
    else:
        recv_size = 64 * 1024

    signal.signal(signal.SIGINT, signal_handler)

    s = socket.socket(getfamily(args), get_socktype(args.socktype))
    s.bind(getaddress(args))

    if args.socktype != "dgram":
        s.listen()
        conn, (cid, port) = s.accept()

    if args.recv:
        if args.socktype == "dgram":
            data, _ = s.recvfrom(recv_size)
        else:
            data = conn.recv(recv_size)
        print(data.decode())
        exit(0)

    print("Press ctrl+c to exit the program")

    i = 0

    start_monitor()
    
    while not done.is_set():
        if args.socktype == "dgram":
            data, _ = s.recvfrom(recv_size)
        else:
            data = conn.recv(recv_size)

        if i == 0:
            start = timer()
            print("read size set to", recv_size)
        else:
            total += len(data)

        i += 1
