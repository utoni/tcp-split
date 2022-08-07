#!/usr/bin/env python3

"""
Follow/Split TCP streams with scapy.
"""

import argparse
import scapy
import scapy.all
import sys
import time

import TCPStream
import TCPStreamExtractor


MAX_BYTES_PER_PACKET = 2


class TCPSplitStreamException(Exception):

    def __init__(self, msg):
        super(Exception, self).__init__(msg)


class TCPSplitData(object):

    def __init__(self, pkt_timestamp, pkt_direction, pkt_payload):
        self.time = pkt_timestamp
        self.direction = pkt_direction # False if src->dst, True otherwise
        self.payload = pkt_payload


class TCPSplitStream(object):

    def __init__(self, tcp_stream: TCPStream.TCPStream):
        if not isinstance(tcp_stream, TCPStream.TCPStream):
            raise TypeError('Got type ' + str(type(tcp_stream)) +
                            ', expected ' + str(TCPStream.TCPStream))
        self.stream = tcp_stream
        self.ordered_pkts = self.stream.get_order_pkts()
        self.ip2dst = scapy.all.IP(src = self.stream.src, dst = self.stream.dst)
        self.ip2src = scapy.all.IP(src = self.stream.dst, dst = self.stream.src)
        if self.stream.tcp_state.syn_seen is True:
            self.seq = self.ordered_pkts[0][scapy.all.TCP].seq # TCP-SYN
            self.ack = self.ordered_pkts[1][scapy.all.TCP].seq # TCP-SYN-ACK
        else:
            self.seq = self.ordered_pkts[0][scapy.all.TCP].seq
            self.ack = self.ordered_pkts[1][scapy.all.TCP].ack

    def __generate_handshake(self):
        if self.stream.tcp_state.syn_seen is False:
            return list()

        syn = scapy.all.TCP(sport = self.stream.sport, dport = self.stream.dport,
                            flags = 'S', seq = self.seq, ack = 0)
        self.seq += 1
        synack = scapy.all.TCP(sport = self.stream.dport, dport = self.stream.sport,
                               flags = 'SA', seq = self.ack, ack = self.seq)
        self.ack += 1
        ack = scapy.all.TCP(sport = self.stream.sport, dport = self.stream.dport,
                            flags = 'A', seq = self.seq, ack = self.ack)

        handshake = list()
        handshake += self.ip2dst/syn
        handshake += self.ip2src/synack
        handshake += self.ip2dst/ack
        handshake[0].time = self.ordered_pkts[0].time # time(TCP-SYN)
        handshake[1].time = self.ordered_pkts[1].time # time(TCP-SYN-ACK)
        handshake[2].time = self.ordered_pkts[2].time # time(TCP-ACK)
        return handshake

    def __generate_payload(self, split_data, bytes_per_packet):
        packets = list()

        for i in range(0, len(split_data.payload), bytes_per_packet):
            payload = split_data.payload[i:i + bytes_per_packet]
            if split_data.direction is False: # reverse direction e.g. server -> client?
                iphdr_src = self.ip2src
                iphdr_dst = self.ip2dst
                tcphdr_sport = self.stream.sport
                tcphdr_dport = self.stream.dport
                tcphdr_seq = self.seq
                tcphdr_ack = self.ack
            else:
                iphdr_src = self.ip2dst
                iphdr_dst = self.ip2src
                tcphdr_sport = self.stream.dport
                tcphdr_dport = self.stream.sport
                tcphdr_seq = self.ack
                tcphdr_ack = self.seq

            iphdr = iphdr_dst
            tcphdr = scapy.all.TCP(sport = tcphdr_sport, dport = tcphdr_dport,
                                   flags = 'PA', seq = tcphdr_seq, ack = tcphdr_ack)
            p = iphdr/tcphdr/scapy.all.Raw(load = payload)
            p.time = split_data.time
            packets += p
            tcphdr_seq += len(payload)

            iphdr = iphdr_src
            tcphdr = scapy.all.TCP(sport = tcphdr_dport, dport = tcphdr_sport,
                                   flags = 'A', seq = tcphdr_ack, ack = tcphdr_seq)
            p = iphdr/tcphdr
            p.time = split_data.time
            packets += p

            if split_data.direction is False:
                self.seq = tcphdr_seq
                self.ack = tcphdr_ack
            else:
                self.seq = tcphdr_ack
                self.ack = tcphdr_seq

        return packets

    def __generate_finish(self, split_data):
        packets = list()

        # We are always closing the connection from the client side for now.
        iphdr = self.ip2dst
        tcphdr = scapy.all.TCP(sport = self.stream.sport, dport = self.stream.dport,
                               flags = 'FA', seq = self.seq, ack = self.ack)
        p = iphdr/tcphdr
        p.time = split_data.time
        packets += p
        self.seq += 1

        iphdr = self.ip2src
        tcphdr = scapy.all.TCP(sport = self.stream.dport, dport = self.stream.sport,
                               flags = 'FA', seq = self.ack, ack = self.seq)
        p = iphdr/tcphdr
        p.time = split_data.time
        packets += p
        self.ack += 1

        iphdr = self.ip2dst
        tcphdr = scapy.all.TCP(sport = self.stream.sport, dport = self.stream.dport,
                               flags = 'A', seq = self.seq, ack = self.ack)
        p = iphdr/tcphdr
        p.time = split_data.time
        packets += p

        return packets

    @staticmethod
    def build_stream_key(pkt):
        return str(pkt['IP'].src) + ':' + str(pkt['TCP'].sport) + \
               ' -> ' + \
               str(pkt['IP'].dst) + ':' + str(pkt['TCP'].dport)

    def split(self):
        data = []
        seq_nos = {}
        for pkt in self.ordered_pkts:
            tcpp = pkt[scapy.all.TCP]
            seq = tcpp.seq
            key = TCPSplitStream.build_stream_key(pkt)
            if not key in seq_nos:
                seq_nos[key] = []

            if seq in seq_nos[key]:
                # retransmit
                continue

            if scapy.all.Raw in tcpp:
                data.append(TCPSplitData(pkt.time, False if pkt.sport == self.stream.sport else True,
                                         tcpp[scapy.all.Raw].load))
                seq_nos[key].append(seq)

        tcp_stream = self.__generate_handshake()

        data.sort(key = lambda tcp_split_data: tcp_split_data.time)
        for payload_packet in data:
            tcp_stream += self.__generate_payload(payload_packet, MAX_BYTES_PER_PACKET)

        tcp_stream += self.__generate_finish(data[-1:][0])

        return tcp_stream


def printStreams(tse):
    print('TCP Streams found:')
    for stream in tse.summary():
        print('\t' + stream)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=str, help='PCAP input file')
    parser.add_argument('-o', '--output', type=str, help='PCAP output file',
                        default=None)
    parser.add_argument('-s', '--summary', action="store_true",
                        help='Print found TCP Streams to stdout',
                        default=False)
    parser.add_argument('-l', '--length', type=int,
                        help='Split TCP payload every n bytes',
                        default=MAX_BYTES_PER_PACKET)
    args = parser.parse_args()

    tse = TCPStreamExtractor.TCPStreamExtractor(args.input)
    if args.summary is True:
        printStreams(tse)

    MAX_BYTES_PER_PACKET = args.length

    all_streams = list()
    for session in tse.fwd_flows:
        stream = tse.streams[session]
        tss = TCPSplitStream(stream)
        all_streams += tss.split()

    if args.output is not None:
        scapy.all.wrpcap(args.output, all_streams)
