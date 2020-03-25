from ipaddress import IPv4Address
from random import randint, getrandbits
from typing import List

from tests.marine.benchmark.conversation_generators import (
    generate_raw_tcp_conversation,
    generate_raw_udp_conversation,
)
from tests.marine.benchmark.utils import ConversationGenerator, IpPair, BenchmarkPacket

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
    return list(macs)


def generate_ips(count: int) -> List[str]:
    if count % 2 != 0:
        count += 1
    ips = set()
    while len(ips) < count:
        ips.add(str(IPv4Address(getrandbits(32))))
    return list(ips)


def generate_ip_pairs(ip_count: int) -> List[IpPair]:
    ips = generate_ips(ip_count * 2)
    macs = generate_macs(ip_count * 2)
    # The list is already randomly generated, so taking consecutive values is random enough
    return [
        IpPair(macs[i], macs[i + 1], ips[i], ips[i + 1])
        for i in range(0, ip_count * 2, 2)
    ]


def generate_packets(count: int) -> List[BenchmarkPacket]:
    benchmark_packets = []
    ip_pairs = generate_ip_pairs(count // 1000)
    packets_per_ip_pair = count // len(ip_pairs)
    for ip_pair in ip_pairs:
        for conversation_generator in CONVERSATION_GENERATORS:
            benchmark_packets.extend(
                conversation_generator.generator(
                    ip_pair,
                    int(
                        packets_per_ip_pair
                        * conversation_generator.percentage_of_packets
                    ),
                )
            )
    return benchmark_packets
