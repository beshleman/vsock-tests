#!/usr/bin/python3

import argparse
import socket
import sys
import signal
import sys
from timeit import default_timer as timer

tot = 0
start = None

def signal_handler(sig, frame):
    if start:
        end = timer()
        elp = end - start
        print("time ", end - start)
        print("speed", tot / elp / 1024 )
    print("total bytes", tot)
    sys.exit(0)

def get_socktype(s):
    return {
        "stream": socket.SOCK_STREAM,
        "dgram": socket.SOCK_DGRAM,
        "seqpacket": socket.SOCK_SEQPACKET,
    }.get(s)

def print_current(iteration, data):
    print(iteration, "messages received")
    length = len(data)
    printsize = min(length, 32)
    post_text = ""
    if printsize > length:
        post_text = "..."
    print("message(%s): %s" % (length, data[:printsize]), post_text)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("socktype", choices=["stream", "dgram", "seqpacket"])
    parser.add_argument("port", type=int)
    parser.add_argument("--fuzz", action="store_true", help="Accept fuzzing clients. Defaults read size to 16KB")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    s = socket.socket(socket.AF_VSOCK, get_socktype(args.socktype))
    s.bind((socket.VMADDR_CID_HOST, args.port))

    if args.socktype != "dgram":
        s.listen()
        conn, (cid, port) = s.accept()

    print("Press ctrl+c to exit the program")

    i = 0
    if args.fuzz:
        recv_size = 16 * 1024
    else:
        recv_size = 16
    
    while True:
        if args.socktype == "dgram":
            data, _ = s.recvfrom(recv_size)
        else:
            data = conn.recv(recv_size)

        if i == 0:
            start = timer()
            if not args.fuzz:
                recv_size = int(data.decode("ascii"))
            print("read size set to", recv_size)
        else:
            tot += len(data)

        if data:
            i += 1
            if i % 100 == 0:
                print_current(i, data)
