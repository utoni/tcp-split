tcp-split
=========

This project is mostly used for my personal research and testing purposes.

Split TCP segments of a stream into smaller ones using Scapy and PCAP files.
Inspired and Copy&Paste from [scapy-tcp-extractor](https://github.com/deeso/scapy-tcp-extractor).

```shell
usage: TCPSplit.py [-h] [-o OUTPUT] [-s] [-l LENGTH] [-b BPF] input

positional arguments:
  input                 PCAP input file

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        PCAP output file
  -s, --summary         Print found TCP Streams to stdout
  -l LENGTH, --length LENGTH
                        Split TCP payload every n bytes
  -b BPF, --bpf BPF     BPF filter to apply
```

You can use the `example.pcapng` which contains two TCP Streams with some ASCII content by typing:

`./TCPSplit.py -o ./splitted.pcap -l1 -s ./example.pcapng`

This will print a summary of all found TCP streams and split the TCP segments into segments of 1 byte size. The resulting `splitted.pcap` file should contain valid TCP streams.
