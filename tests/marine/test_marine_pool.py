from typing import List

import pytest
from pypacker.layer12 import ethernet, arp
from pypacker.pypacker import Packet

from marine.marine_pool import MarinePool


def generate_arp_packet(src_ip: str, target_ip: str) -> Packet:
    src_mac = "00:00:00:12:34:ff"
    broadcast_mac = "ff:ff:ff:ff:ff:ff"

    return ethernet.Ethernet(src_s=src_mac, dst_s=broadcast_mac) + arp.ARP(
        sha_s=src_mac, spa_s=src_ip, tha_s=broadcast_mac, tpa_s=target_ip
    )


@pytest.fixture
def passing_src_ip() -> str:
    return "2.2.2.2"


@pytest.fixture
def not_passing_src_ip() -> str:
    return "3.3.3.3"


@pytest.fixture
def arp_packets(passing_src_ip: str, not_passing_src_ip: str) -> List[Packet]:
    packets = []
    for i in range(10):
        target_ip = f"1.1.1.{i}"
        src_ip = passing_src_ip if i % 2 == 0 else not_passing_src_ip
        packets.append(generate_arp_packet(src_ip, target_ip))
    return packets


def test_marine_pool_preserves_order(
    marine_pool_instance: MarinePool, arp_packets: List[Packet], passing_src_ip: str
) -> None:
    TARGET_IP_FIELD_NAME = "arp.dst.proto_ipv4"

    raw_packets = [packet.bin() for packet in arp_packets]
    results = marine_pool_instance.filter_and_parse(
        raw_packets, bpf=f"arp net {passing_src_ip}", fields=[TARGET_IP_FIELD_NAME]
    )

    for arp_packet, filter_and_parse_result in zip(arp_packets, results):
        expected_target_ip = arp_packet.highest_layer.tpa_s
        passed, actual_fields = filter_and_parse_result
        assert passed == (arp_packet.highest_layer.spa_s == passing_src_ip)
        if passed:
            assert expected_target_ip == actual_fields[TARGET_IP_FIELD_NAME]
