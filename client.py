#!/usr/bin/python3

import argparse
import socket
import sys
import time
import signal
import os
import random
import time
from threading import Timer

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

msgs = 0
total = 0
first_time = None
last_time = None
timer = None

def start_monitor():
    global first_time
    global last_time
    global timer

    if timer:
        timer.cancel()

    last_time = t = time.time()
    if first_time is None:
        first_time = t
    print("{}: msgs={}, data={}".format(t, msgs, Size.human_readable(total)))
    timer = Timer(3, start_monitor)
    timer.start()

def signal_handler(sig, frame):
    if timer:
        timer.cancel()
    print("total", total)
    if last_time is not None and first_time is not None:
        elapsed = last_time - first_time
        print("elapsed:", round(elapsed, 2))
        print("rate:", Size.human_readable(total / elapsed) + "/s")
    sys.exit(0)

def get_socktype(s):
    return {
        "stream": socket.SOCK_STREAM,
        "dgram": socket.SOCK_DGRAM,
        "seqpacket": socket.SOCK_SEQPACKET,
    }.get(s)

def get_send_func(socktype, socket, cid, port):
    def dgram_send(data):
        return s.sendto(data, (cid, port))

    def stream_send(data):
        cnt = 0
        if s.sendall(data) is None:
            cnt = len(data)
        return cnt

    if socktype == "dgram":
        return dgram_send

    return stream_send

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("socktype", choices=["stream", "dgram", "seqpacket"])
    parser.add_argument("cid", type=int)
    parser.add_argument("port", type=int)
    parser.add_argument("--size", type=int, default=4096, help="The payload size")
    parser.add_argument("--fuzz", action="store_true", help="Fuzz the socket. Arg --size defines maximum input size")
    args = parser.parse_args()

    maxsize = int("9" * 16)
    if args.size > maxsize:
        print("--size must be smaller than", maxsize)
        sys.exit(-1)

    signal.signal(signal.SIGINT, signal_handler)

    s = socket.socket(socket.AF_VSOCK, get_socktype(args.socktype), 0)

    if args.socktype != "dgram":
        addr = (args.cid, args.port)
        print("connecting to {}".format(repr(addr)))
        s.connect(addr)

    print("Press ctrl+c to exit the program")

    start_monitor()

    send = get_send_func(args.socktype, s, args.cid, args.port)
    if not args.fuzz:
        # Send 16 characters containing the future payload size
        first_message = str(args.size).zfill(16).encode('ascii')
        send(first_message)

    i = 0
    while True:
        if args.fuzz:
            data = os.urandom(random.randint(1, args.size))
        else:
            data =  str(i)[0].encode('ascii') * (args.size)
        cnt = send(data)
        msgs += 1
        if cnt > 0:
            total += cnt
        i += 1
