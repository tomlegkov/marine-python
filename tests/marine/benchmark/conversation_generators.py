import os
from random import randint
from typing import List, Callable, Dict, Tuple

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp, udp
from pypacker.pypacker import Packet

from .utils import Layer3Conversation, BenchmarkPacket


def _generate_port() -> int:
    return randint(10000, 60000)


def _create_tcp_base_packets(conversation: Layer3Conversation) -> Tuple[Packet, Packet]:
    src_port, dst_port = _generate_port(), _generate_port()
    base_src_to_dst = (
        ethernet.Ethernet(
            src_s=conversation.src_mac,
            dst_s=conversation.dst_mac,
            type=ethernet.ETH_TYPE_IP,
        )
        + ip.IP(p=ip.IP_PROTO_TCP, src_s=conversation.src_ip, dst_s=conversation.dst_ip)
        + tcp.TCP(sport=src_port, dport=dst_port)
    )
    base_dst_to_src = (
        ethernet.Ethernet(
            src_s=conversation.dst_mac,
            dst_s=conversation.src_mac,
            type=ethernet.ETH_TYPE_IP,
        )
        + ip.IP(p=ip.IP_PROTO_TCP, src_s=conversation.dst_ip, dst_s=conversation.src_ip)
        + tcp.TCP(sport=dst_port, dport=src_port)
    )

    return base_src_to_dst, base_dst_to_src


def _create_udp_base_packets(conversation: Layer3Conversation) -> Tuple[Packet, Packet]:
    src_port, dst_port = _generate_port(), _generate_port()
    base_src_to_dst = (
        ethernet.Ethernet(
            src_s=conversation.src_mac,
            dst_s=conversation.dst_mac,
            type=ethernet.ETH_TYPE_IP,
        )
        + ip.IP(p=ip.IP_PROTO_UDP, src_s=conversation.src_ip, dst_s=conversation.dst_ip)
        + udp.UDP(sport=src_port, dport=dst_port)
    )
    base_dst_to_src = (
        ethernet.Ethernet(
            src_s=conversation.dst_mac,
            dst_s=conversation.src_mac,
            type=ethernet.ETH_TYPE_IP,
        )
        + ip.IP(p=ip.IP_PROTO_UDP, src_s=conversation.dst_ip, dst_s=conversation.src_ip)
        + udp.UDP(sport=dst_port, dport=src_port)
    )

    return base_src_to_dst, base_dst_to_src


def _generate_conversation(
    base_src_to_dst: Packet,
    base_dst_to_src: Packet,
    packet_generator: Callable[[Packet], BenchmarkPacket],
    conversation_length: int,
) -> List[BenchmarkPacket]:
    packets: List[BenchmarkPacket] = []
    total_sent = 0
    clients_turn = True

    while total_sent < conversation_length:
        packet_count = randint(1, 3)
        if packet_count + total_sent > conversation_length:
            packet_count = conversation_length - total_sent

        for i in range(packet_count):
            packet = base_src_to_dst if clients_turn else base_dst_to_src
            packets.append(packet_generator(packet))

        clients_turn = not clients_turn
        total_sent += packet_count

    return packets


def _get_up_to_layer_3_expected_fields(packet: Packet) -> Dict[str, str]:
    return {
        "eth.src": packet[ethernet.Ethernet].src_s.lower(),
        "eth.dst": packet[ethernet.Ethernet].dst_s.lower(),
        "ip.src": packet[ip.IP].src_s,
        "ip.dst": packet[ip.IP].dst_s,
        "ip.proto": str(packet[ip.IP].p),
    }


def generate_raw_tcp_conversation(
    conversation: Layer3Conversation, conversation_length: int
) -> List[BenchmarkPacket]:
    base_src_to_dst, base_dst_to_src = _create_tcp_base_packets(conversation)

    def _create_packet(base_layer: Packet) -> BenchmarkPacket:
        src_port = base_layer[tcp.TCP].sport
        dst_port = base_layer[tcp.TCP].dport
        data_len = randint(100, 1000)
        base_layer[tcp.TCP].body_bytes = os.urandom(data_len)
        layer_3_expected_fields = _get_up_to_layer_3_expected_fields(base_layer)
        expected_parse_result = {
            "tcp.len": str(data_len),
            "tcp.srcport": str(src_port),
            "tcp.dstport": str(dst_port),  # TODO change this when Marine supports types
        }
        expected_parse_result.update(layer_3_expected_fields)
        return BenchmarkPacket(
            base_layer.bin(),
            good_bpf=f"tcp src port {src_port} and tcp dst port {dst_port}",
            good_display_filter=f"tcp.srcport == {src_port} and tcp.dstport == {dst_port}",
            fields_to_extract=list(layer_3_expected_fields.keys())
            + ["tcp.len", "tcp.srcport", "tcp.dstport"],
            expected_parse_result=expected_parse_result,
        )

    return _generate_conversation(
        base_src_to_dst, base_dst_to_src, _create_packet, conversation_length
    )


def generate_raw_udp_conversation(
    conversation: Layer3Conversation, conversation_length: int
) -> List[BenchmarkPacket]:
    base_src_to_dst, base_dst_to_src = _create_udp_base_packets(conversation)

    def _create_packet(base_layer: Packet) -> BenchmarkPacket:
        src_port = base_layer[udp.UDP].sport
        dst_port = base_layer[udp.UDP].dport
        data_len = randint(100, 1000)
        base_layer[udp.UDP].body_bytes = os.urandom(data_len)
        layer_3_expected_fields = _get_up_to_layer_3_expected_fields(base_layer)
        expected_parse_result = {
            "udp.length": str(data_len + base_layer[udp.UDP].header_len),
            "udp.srcport": str(src_port),
            "udp.dstport": str(dst_port),  # TODO change this when Marine supports types
        }
        expected_parse_result.update(layer_3_expected_fields)
        return BenchmarkPacket(
            base_layer.bin(),
            good_bpf=f"udp src port {src_port} and udp dst port {dst_port}",
            good_display_filter=f"udp.srcport == {src_port} and udp.dstport == {dst_port}",
            fields_to_extract=list(layer_3_expected_fields)
            + ["udp.length", "udp.srcport", "udp.dstport"],
            expected_parse_result=expected_parse_result,
        )

    return _generate_conversation(
        base_src_to_dst, base_dst_to_src, _create_packet, conversation_length
    )
