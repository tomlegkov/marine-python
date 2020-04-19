import pytest
from pypacker.layer12 import ethernet, arp

from marine import MarinePool


def generate_arp_packet(target_ip):
    src_mac = "00:00:00:12:34:ff"
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    src_ip = "2.2.2.2"

    return ethernet.Ethernet(src_s=src_mac, dst_s=broadcast_mac) + arp.ARP(
        sha_s=src_mac, spa_s=src_ip, tha_s=broadcast_mac, tpa_s=target_ip
    )


@pytest.fixture
def arp_packets():
    target_ips = [f"1.1.1.{i}" for i in range(10)]
    return [generate_arp_packet(target_ip) for target_ip in target_ips]


def test_marine_pool_preserves_order(marine_pool_instance: MarinePool, arp_packets):
    TARGET_IP_FIELD_NAME = "arp.dst.proto_ipv4"

    raw_packets = [packet.bin() for packet in arp_packets]
    results = marine_pool_instance.filter_and_parse(
        raw_packets, bpf="1=1", fields=[TARGET_IP_FIELD_NAME]
    )
    for arp_packet, filter_and_parse_result in zip(arp_packets, results):
        expected_target_ip = arp_packet.highest_layer.tpa_s
        passed, actual_fields = filter_and_parse_result
        assert expected_target_ip == actual_fields[TARGET_IP_FIELD_NAME]
