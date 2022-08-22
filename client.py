#!/usr/bin/python3

import argparse
import socket
import sys
import signal
import os
import random
import time
from multiprocessing import Process, Value
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


parent_pid = os.getpid()
msgs = 0
total = 0

msg_counts = []
totals = []

first_time = time.time()
timer = None
processes = []
timeout = -1

def acquire_all(values):
    l = [v.get_lock() for v in values]
    for lock in l:
        lock.acquire()
    return l

def release_all(locks):
    for l in locks:
        l.release()

def get_total():
    total = 0
    locks = acquire_all(totals)
    for t in totals:
        total += t.value
    release_all(locks)
    return total


def print_per_thread_total():
    total = 0
    for tid,t in enumerate(totals):
        print("\ttid-{} has sent {}".format(tid, Size.human_readable(t.value)))

def get_msg_count():
    total_msg_count = 0
    locks = acquire_all(msg_counts)
    for msg_count in msg_counts:
        total_msg_count +=  msg_count.value
    release_all(locks)
    return total_msg_count

def print_traffic_data(timestamp):
    msg_count = get_msg_count()
    total = get_total()
    print("{}: msgs={}, data={}".format(
        round(timestamp, 2), msg_count, Size.human_readable(total)))

def cleanup():
    global timer
    if timer:
        timer.cancel()
        timer = None

def get_elapsed():
    return round(time.time() - first_time, 2)

def start_monitor():
    global first_time
    global timer

    if timeout != -1 and get_elapsed() > timeout:
        cleanup()
        sys.exit(0)

    print_traffic_data(time.time())
    print_per_thread_total()
    if timer:
        timer.cancel()
    timer = Timer(3, start_monitor)
    timer.start()

def signal_handler(sig, frame):
    cleanup()
    if os.getpid() == parent_pid:
        total = get_total()
        elapsed = get_elapsed()
        print("total", Size.human_readable(total))
        print("elapsed:", elapsed)
        print("rate:", Size.human_readable(total / elapsed) + "/s")
    exit(0)

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

def main_loop(send, fuzz, size, tid=-1):
    global msg_counts
    global totals

    if tid == -1:
        tid = 0
        msg_counts.append(Value("Q", 0))
        totals.append(Value("Q", 0))

    msgs = msg_counts[tid]
    total = totals[tid]

    i = 0
    while True:
        if fuzz:
            data = os.urandom(random.randint(1, size))
        else:
            data =  str(i)[0].encode('ascii') * size
        cnt = send(data)

        with msgs.get_lock():
            msgs.value += 1

        if cnt > 0:
            with total.get_lock():
                total.value += cnt
        i += 1

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("socktype", choices=["stream", "dgram", "seqpacket"])
    parser.add_argument("cid", type=int)
    parser.add_argument("port", type=int)
    parser.add_argument("--size", type=int, default=4096, help="The payload size")
    parser.add_argument("--fuzz", action="store_true", help="Fuzz the socket. Arg --size defines maximum input size")
    parser.add_argument("--threads", type=int, default=1, help="The number of threads")
    parser.add_argument("--timeout", type=int, default=-1, help="The number of seconds to run the test")
    args = parser.parse_args()

    if args.threads < 1:
        print("--threads must be at least 1")
        sys.exit(-1)

    if args.timeout != -1 and args.timeout < 0:
        print("--timeout must be a positive integer")
        sys.exit(-1)

    timeout = args.timeout

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

    if args.threads > 1:
        for tid in range(args.threads):
            msg_counts.append(Value("Q", 0))
            totals.append(Value("Q", 0))
            p = Process(target=main_loop, args=(send, args.fuzz, args.size, tid))
            p.start()
            processes.append(p)
        for p in processes:
            p.join()
    else:
        main_loop(send, args.fuzz, args.size)
