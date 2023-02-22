#!/usr/bin/python3

import argparse
import socket
import sys
import signal
import sys
from threading import Timer
from timeit import default_timer as timer

t = None
total = 0
start = None

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
    if start:
        end = timer()
        elp = end - start
        print("time ", end - start)
        print("speed", total / elp / 1024 )
    print("total bytes", Size.human_readable(total))
    sys.exit(0)

def get_socktype(s):
    return {
        "stream": socket.SOCK_STREAM,
        "dgram": socket.SOCK_DGRAM,
        "seqpacket": socket.SOCK_SEQPACKET,
    }.get(s)

def print_traffic_data():
    print("data received={}".format(Size.human_readable(total)))

def start_monitor():
    global t

    if t:
        t.cancel()

    print_traffic_data()

    t = Timer(3, start_monitor)
    t.start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("socktype", choices=["stream", "dgram", "seqpacket"])
    parser.add_argument("port", type=int)
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    s = socket.socket(socket.AF_INET, get_socktype(args.socktype))
    s.bind(('0.0.0.0', args.port))

    if args.socktype != "dgram":
        s.listen()
        conn, (ip, port) = s.accept()

    print("Press ctrl+c to exit the program")

    i = 0
    recv_size = 64 * 1024

    start_monitor()
    
    while True:
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
