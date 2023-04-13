# vsock-tests

This repo contains tools for testing vsock.

STREAM, DGRAM, and SEQPACKET are all supported.


On the server side, execute server.py:

```
usage: server.py [-h] {stream,dgram,seqpacket} port

positional arguments:
  {stream,dgram,seqpacket}
  port

optional arguments:
  -h, --help            show this help message and exit
```

On the client side, execute client.py:

```
usage: client.py [-h] [--size SIZE] [--threads THREADS]
                 [--timeout TIMEOUT]
                 {stream,dgram,seqpacket} cid port

positional arguments:
  {stream,dgram,seqpacket}
  cid
  port

optional arguments:
  -h, --help            show this help message and exit
  --size SIZE           The payload size
  --threads THREADS     The number of threads
  --timeout TIMEOUT     The number of seconds to run the test
```


## Example

```
# On host/server side
./server.py seqpacket 1234

# On guest/client side.
# Messages of length 1 of random bytes over seqpacket to CID 2 and port 1234.
./client.py seqpacket 2 1234 --size 1
````
