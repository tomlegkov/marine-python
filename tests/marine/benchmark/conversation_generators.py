from functools import wraps
from random import randint
from secrets import token_bytes
from typing import List, Callable

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp, udp
from pypacker.pypacker import Packet

from tests.marine.benchmark.utils import IpPair, BenchmarkPacket


def udp_base_layer(
    fn: Callable[[Packet, Packet, int], List[BenchmarkPacket]]
) -> Callable[[IpPair, int], List[BenchmarkPacket]]:
    @wraps(fn)
    def inner_udp_base_layer(
        ip_pair: IpPair, conversation_length: int
    ) -> List[BenchmarkPacket]:
        src_port, dst_port = ip_pair.generate_port_pair()

        base_src_to_dst = (
            ethernet.Ethernet(
                src_s=ip_pair.src_mac, dst_s=ip_pair.dst_mac, type=ethernet.ETH_TYPE_IP
            )
            + ip.IP(p=ip.IP_PROTO_UDP, src_s=ip_pair.src_ip, dst_s=ip_pair.dst_ip)
            + udp.UDP(sport=src_port, dport=dst_port)
        )
        base_dst_to_src = (
            ethernet.Ethernet(
                src_s=ip_pair.dst_mac, dst_s=ip_pair.src_mac, type=ethernet.ETH_TYPE_IP
            )
            + ip.IP(p=ip.IP_PROTO_UDP, src_s=ip_pair.dst_ip, dst_s=ip_pair.src_ip)
            + udp.UDP(sport=dst_port, dport=src_port)
        )

        return fn(base_src_to_dst, base_dst_to_src, conversation_length)

    return inner_udp_base_layer


def tcp_base_layer(
    fn: Callable[[Packet, Packet, int], List[BenchmarkPacket]]
) -> Callable[[IpPair, int], List[BenchmarkPacket]]:
    @wraps(fn)
    def inner_tcp_base_layer(
        ip_pair: IpPair, conversation_length: int
    ) -> List[BenchmarkPacket]:
        src_port, dst_port = ip_pair.generate_port_pair()

        base_src_to_dst = (
            ethernet.Ethernet(
                src_s=ip_pair.src_mac, dst_s=ip_pair.dst_mac, type=ethernet.ETH_TYPE_IP
            )
            + ip.IP(p=ip.IP_PROTO_TCP, src_s=ip_pair.src_ip, dst_s=ip_pair.dst_ip)
            + tcp.TCP(sport=src_port, dport=dst_port)
        )
        base_dst_to_src = (
            ethernet.Ethernet(
                src_s=ip_pair.dst_mac, dst_s=ip_pair.src_mac, type=ethernet.ETH_TYPE_IP
            )
            + ip.IP(p=ip.IP_PROTO_TCP, src_s=ip_pair.dst_ip, dst_s=ip_pair.src_ip)
            + tcp.TCP(sport=dst_port, dport=src_port)
        )

        return fn(base_src_to_dst, base_dst_to_src, conversation_length)

    return inner_tcp_base_layer


def conversation_generator(
    fn: Callable[[Packet], BenchmarkPacket]
) -> Callable[[], List[BenchmarkPacket]]:
    @wraps(fn)
    def inner_conversation_generator(
        base_src_to_dst: Packet, base_dst_to_src: Packet, conversation_length: int
    ) -> List[BenchmarkPacket]:
        packets = []
        total_sent = 0
        clients_turn = True

        while total_sent < conversation_length:
            packet_count = randint(1, 3)
            if packet_count + total_sent > conversation_length:
                packet_count = conversation_length - total_sent

            for i in range(packet_count):
                packet = base_src_to_dst if clients_turn else base_dst_to_src
                packets.append(fn(packet))

            clients_turn = not clients_turn
            total_sent += packet_count

        return packets

    return inner_conversation_generator


@tcp_base_layer
@conversation_generator
def generate_raw_tcp_conversation(packet: Packet) -> BenchmarkPacket:
    src_port = packet[tcp.TCP].sport
    dst_port = packet[tcp.TCP].dport
    data_len = randint(100, 1000)
    packet[tcp.TCP].body_bytes = token_bytes(data_len)
    return BenchmarkPacket(
        packet.bin(),
        good_bpf=f"tcp src port {src_port} and tcp dst port {dst_port}",
        good_display_filter=f"tcp.srcport == {src_port} and tcp.dstport == {dst_port}",
        fields_to_extract=[
            "eth.src",
            "eth.dst",
            "ip.src",
            "ip.dst",
            "ip.proto",
            "tcp.len",
            "tcp.srcport",
            "tcp.dstport",
        ],
        expected_parse_result={
            "eth.src": packet[ethernet.Ethernet].src_s.lower(),
            "eth.dst": packet[ethernet.Ethernet].dst_s.lower(),
            "ip.src": packet[ip.IP].src_s,
            "ip.dst": packet[ip.IP].dst_s,
            "ip.proto": str(packet[ip.IP].p),
            "tcp.len": str(data_len),
            "tcp.srcport": str(src_port),
            "tcp.dstport": str(dst_port),  # TODO change this when Marine supports types
        },
    )


@udp_base_layer
@conversation_generator
def generate_raw_udp_conversation(packet: Packet) -> BenchmarkPacket:
    src_port = packet[udp.UDP].sport
    dst_port = packet[udp.UDP].dport
    data_len = randint(100, 1000)
    packet[udp.UDP].body_bytes = token_bytes(data_len)
    return BenchmarkPacket(
        packet.bin(),
        good_bpf=f"udp src port {src_port} and udp dst port {dst_port}",
        good_display_filter=f"udp.srcport == {src_port} and udp.dstport == {dst_port}",
        fields_to_extract=[
            "eth.src",
            "eth.dst",
            "ip.src",
            "ip.dst",
            "ip.proto",
            "udp.length",
            "udp.srcport",
            "udp.dstport",
        ],
        expected_parse_result={
            "eth.src": packet[ethernet.Ethernet].src_s.lower(),
            "eth.dst": packet[ethernet.Ethernet].dst_s.lower(),
            "ip.src": packet[ip.IP].src_s,
            "ip.dst": packet[ip.IP].dst_s,
            "ip.proto": str(packet[ip.IP].p),
            "udp.length": str(data_len + packet[udp.UDP].header_len),
            "udp.srcport": str(src_port),
            "udp.dstport": str(dst_port),  # TODO change this when Marine supports types
        },
    )
