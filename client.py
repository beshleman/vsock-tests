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

msgs = 0
total = 0

def start_monitor():
    t = time.time()
    print("{}: msgs={}, bytes={}".format(t, msgs, total))
    Timer(3, start_monitor).start()

def signal_handler(sig, frame):
    print("total", total)
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
