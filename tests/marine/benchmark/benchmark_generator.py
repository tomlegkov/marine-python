from ipaddress import IPv4Address
from random import randint, getrandbits, shuffle
from typing import List

from .conversation_generators import (
    generate_raw_tcp_conversation,
    generate_raw_udp_conversation,
)
from .utils import ConversationGenerator, Layer3Conversation, BenchmarkPacket

CONVERSATION_GENERATORS = [
    ConversationGenerator(0.5, generate_raw_tcp_conversation),
    ConversationGenerator(0.5, generate_raw_udp_conversation),
]


def create_random_mac() -> str:
    return "00:00:00:%02x:%02x:%02x" % (
        randint(0, 255),
        randint(0, 255),
        randint(0, 255),
    )


def generate_macs(count: int) -> List[str]:
    if count % 2 != 0:
        count += 1
    macs = set()
    while len(macs) < count:
        macs.add(str(create_random_mac()))
    mac_list = list(macs)
    shuffle(mac_list)
    return mac_list


def generate_ips(count: int) -> List[str]:
    if count % 2 != 0:
        count += 1
    ips = set()
    while len(ips) < count:
        ips.add(str(IPv4Address(getrandbits(32))))
    ip_list = list(ips)
    shuffle(ip_list)
    return ip_list


def generate_layer_3_conversations(count: int) -> List[Layer3Conversation]:
    ips = generate_ips(count * 2)
    macs = generate_macs(count * 2)
    # The list is already randomly generated, so taking consecutive values is random enough
    return [
        Layer3Conversation(macs[i], macs[i + 1], ips[i], ips[i + 1])
        for i in range(0, count * 2, 2)
    ]


def generate_packets(count: int) -> List[BenchmarkPacket]:
    benchmark_packets = []
    layer_3_conversations = generate_layer_3_conversations(count // 1000)
    packets_per_conversation = count // len(layer_3_conversations)
    for conversation in layer_3_conversations:
        for conversation_generator in CONVERSATION_GENERATORS:
            benchmark_packets.extend(
                conversation_generator.generator(
                    conversation,
                    int(
                        packets_per_conversation
                        * conversation_generator.percentage_of_packets
                    ),
                )
            )
    return benchmark_packets
