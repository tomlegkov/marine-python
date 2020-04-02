"""
Note: in order to run the tests, you must put libmarine.so next to the marine_fixtures.py file
"""
import pytest
from typing import List, Union, Optional
from marine import Marine

from pypacker.layer12 import ethernet, arp
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import tcp, udp
from pypacker.layer567 import dns, http, dhcp


# TODO: Add a test for FTP.


def general_filter_and_parse_test(
    marine_instance: Marine,
    packet: bytes,
    bpf_filter: Optional[str],
    display_filter: Optional[str],
    extracted_fields_from_packet: List[str],
    expected_values: List[Union[str, int]],
):
    expected = dict(zip(extracted_fields_from_packet, map(str, expected_values)))
    passed, output = marine_instance.filter_and_parse(
        packet, bpf_filter, display_filter, extracted_fields_from_packet
    )

    assert passed
    assert expected == output


def test_arp_packet_filter_and_parse(marine_instance: Marine):
    src_mac = "00:00:00:12:34:ff"
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    src_ip = "21.53.78.255"
    target_ip = "10.0.0.255"
    bpf_filter = "arp"
    display_filter = "arp"
    extracted_fields_from_arp_packet = [
        "eth.src",
        "eth.dst",
        "arp.src.hw_mac",
        "arp.src.proto_ipv4",
        "arp.dst.hw_mac",
        "arp.dst.proto_ipv4",
    ]

    packet = ethernet.Ethernet(src_s=src_mac, dst_s=broadcast_mac) + arp.ARP(
        sha_s=src_mac, spa_s=src_ip, tha_s=broadcast_mac, tpa_s=target_ip
    )

    general_filter_and_parse_test(
        marine_instance=marine_instance,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        extracted_fields_from_packet=extracted_fields_from_arp_packet,
        expected_values=[
            src_mac,
            broadcast_mac,
            src_mac,
            src_ip,
            broadcast_mac,
            target_ip,
        ],
    )


def test_icmp_packet_filter_and_parse(marine_instance: Marine):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    dst_ip = "10.0.0.255"
    icmp_echo_type = 8
    bpf_filter = "ip"
    display_filter = "icmp"
    extracted_fields_from_icmp_packet = [
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "icmp.type",
    ]

    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=dst_ip, p=ip.IP_PROTO_ICMP)
        + icmp.ICMP(type=icmp_echo_type)
        + icmp.ICMP.Echo()
    )

    general_filter_and_parse_test(
        marine_instance=marine_instance,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        extracted_fields_from_packet=extracted_fields_from_icmp_packet,
        expected_values=[src_mac, dst_mac, src_ip, dst_ip, icmp_echo_type],
    )


def test_tcp_packet_filter_and_parse(marine_instance: Marine):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    dst_ip = "10.0.0.255"
    src_port = 16424
    dst_port = 41799
    bpf_filter = "ip"
    display_filter = "tcp"
    extracted_fields_from_tcp_packet = [
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
    ]

    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=dst_ip)
        + tcp.TCP(sport=src_port, dport=dst_port)
    )

    general_filter_and_parse_test(
        marine_instance=marine_instance,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        extracted_fields_from_packet=extracted_fields_from_tcp_packet,
        expected_values=[src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port],
    )


def test_dns_packet_filter_and_parse(marine_instance: Marine):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    dst_ip = "10.0.0.255"
    src_port = 16424
    dst_port = 53
    bpf_filter = "ip"
    display_filter = "dns"
    domain_name = "www.testwebsite.com"
    extracted_fields_from_dns_packet = [
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "udp.srcport",
        "udp.dstport",
        "dns.qry.name",
    ]

    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=dst_ip, p=ip.IP_PROTO_UDP)
        + udp.UDP(sport=src_port, dport=dst_port)
        + dns.DNS(queries=[dns.DNS.Query(name_s=domain_name, type=1, cls=1)])
    )

    general_filter_and_parse_test(
        marine_instance=marine_instance,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        extracted_fields_from_packet=extracted_fields_from_dns_packet,
        expected_values=[
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            domain_name,
        ],
    )


def test_dhcp_packet_filter_and_parse(marine_instance: Marine):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    given_ip = "10.0.0.255"
    broadcast_ip = "255.255.255.255"
    src_port = 16424
    dst_port = 68
    bpf_filter = "ip"
    display_filter = "dhcp"
    extracted_fields_from_dhcp_packet = [
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "udp.srcport",
        "udp.dstport",
        "dhcp.ip.your",
        "dhcp.option.dhcp_server_id",
    ]

    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=broadcast_ip, p=ip.IP_PROTO_UDP)
        + udp.UDP(sport=src_port, dport=dst_port)
        + dhcp.DHCP(
            yiaddr_s=given_ip,
            magic=dhcp.DHCP_MAGIC,
            opts=[
                dhcp.DHCPOpt(
                    type=dhcp.DHCP_OPT_SERVER_ID,
                    len=4,
                    body_bytes=bytes(int(num) for num in src_ip.split(".")),
                )
            ],
        )
    )

    general_filter_and_parse_test(
        marine_instance=marine_instance,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        extracted_fields_from_packet=extracted_fields_from_dhcp_packet,
        expected_values=[
            src_mac,
            dst_mac,
            src_ip,
            broadcast_ip,
            src_port,
            dst_port,
            given_ip,
            src_ip,
        ],
    )


def test_http_packet_filter_and_parse(marine_instance: Marine):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    dst_ip = "10.0.0.255"
    src_port = 16424
    dst_port = 80
    http_type = "GET"
    uri = "/subtest/subsubtest"
    version = "HTTP/1.1"
    domain_name = "www.testwebsite.com"
    body = "random body \x09\xff\x00"
    bpf_filter = "ip"
    display_filter = "http"
    extracted_fields_from_http_packet = [
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "http.request.method",
        "http.request.uri",
        "http.request.version",
        "http.host",
    ]

    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=dst_ip)
        + tcp.TCP(sport=src_port, dport=dst_port)
        + http.HTTP(
            f"{http_type} {uri} {version}\r\nHost: {domain_name}\r\n\r\n{body}\r\n".encode()
        )
    )

    general_filter_and_parse_test(
        marine_instance=marine_instance,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        extracted_fields_from_packet=extracted_fields_from_http_packet,
        expected_values=[
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            http_type,
            uri,
            version,
            domain_name,
        ],
    )


def test_filter_and_parse_without_filters(marine_instance: Marine):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    dst_ip = "10.0.0.255"
    src_port = 16424
    dst_port = 41799
    extracted_fields_from_tcp_packet = [
        "eth.src",
        "eth.dst",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
    ]

    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=dst_ip)
        + tcp.TCP(sport=src_port, dport=dst_port)
    )

    general_filter_and_parse_test(
        marine_instance=marine_instance,
        packet=packet.bin(),
        bpf_filter=None,
        display_filter=None,
        extracted_fields_from_packet=extracted_fields_from_tcp_packet,
        expected_values=[src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port],
    )


def test_filter_and_parse_without_fields(marine_instance: Marine, tcp_packet: bytes):
    passed, output = marine_instance.filter_and_parse(tcp_packet, "ip", "tcp")

    assert passed
    assert output is None


def test_packet_doesnt_pass_filter_because_of_bpf(
    marine_instance: Marine,
    tcp_packet: bytes,
    extracted_fields_from_tcp_packet: List[str],
):
    passed, output = marine_instance.filter_and_parse(
        tcp_packet, "arp", fields=extracted_fields_from_tcp_packet
    )

    assert not passed
    assert output is None


def test_packet_doesnt_pass_filter_because_of_display_filter(
    marine_instance: Marine,
    tcp_packet: bytes,
    extracted_fields_from_tcp_packet: List[str],
):
    passed, output = marine_instance.filter_and_parse(
        tcp_packet, display_filter="udp", fields=extracted_fields_from_tcp_packet
    )

    assert not passed
    assert output is None


def test_illegal_bpf_in_filter_and_parse(marine_instance: Marine, tcp_packet: bytes):
    with pytest.raises(ValueError, match="Failed compiling the BPF"):
        marine_instance.filter_and_parse(tcp_packet, bpf="what is this bpf?")


def test_illegal_display_filter_in_filter_and_parse(
    marine_instance: Marine, tcp_packet: bytes
):
    with pytest.raises(ValueError, match="neither a field nor a protocol name"):
        marine_instance.filter_and_parse(tcp_packet, display_filter="illegal_filter")


def test_illegal_fields_in_filter_and_parse(marine_instance: Marine, tcp_packet: bytes):
    with pytest.raises(ValueError) as excinfo:
        marine_instance.filter_and_parse(
            tcp_packet, fields=["illegal_field_1", "illegal_field_2", "ip.src"]
        )
    err_msg = str(excinfo)

    assert "illegal_field_1" in err_msg
    assert "illegal_field_2" in err_msg
    assert "ip.src" not in err_msg


def test_filter_and_parse_with_no_parameters(
    marine_instance: Marine, tcp_packet: bytes
):
    with pytest.raises(ValueError, match="must be passed"):
        marine_instance.filter_and_parse(tcp_packet)


def test_validate_bpf_success(marine_instance: Marine):
    assert marine_instance.validate_bpf("arp")


def test_validate_bpf_failure(marine_instance: Marine):
    assert not marine_instance.validate_bpf("what is this bpf?")


def test_validate_display_filter_success(marine_instance: Marine):
    assert marine_instance.validate_display_filter("tcp")


def test_validate_display_filter_failure(marine_instance: Marine):
    assert not marine_instance.validate_display_filter("illegal_filter")
