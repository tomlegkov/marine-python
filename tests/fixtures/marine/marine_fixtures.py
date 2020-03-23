import os
from ipaddress import IPv4Address
from random import getrandbits, randint, choices
from typing import TypedDict, List
import string

import pytest
from pypacker.layer12 import ethernet, arp
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import tcp, udp
from pypacker.layer567 import dns, http

from marine import Marine


class HttpDescription(TypedDict):
    http_type: str
    uri: str
    version: str
    host: str
    body: str


def create_random_ip() -> str:
    return str(IPv4Address(getrandbits(32)))


def create_random_mac() -> str:
    return "00:00:00:%02x:%02x:%02x" % (
        randint(0, 255),
        randint(0, 255),
        randint(0, 255),
    )


def create_random_string(length: int) -> str:
    return "".join(choices(string.ascii_lowercase, k=length))


def create_random_url(length: int = 8) -> str:
    return "www.%s.com" % (create_random_string(length))


def create_random_http_get() -> HttpDescription:
    return {
        "http_type": "GET",
        "uri": f"/{create_random_string(8)}",
        "version": "HTTP/1.1",
        "host": create_random_url(),
        "body": create_random_string(20),
    }


@pytest.fixture
def http_get() -> HttpDescription:
    return create_random_http_get()


@pytest.fixture
def url_1() -> str:
    return create_random_url()


@pytest.fixture
def ip_1() -> str:
    return create_random_ip()


@pytest.fixture
def ip_2() -> str:
    return create_random_ip()


@pytest.fixture
def mac_1() -> str:
    return create_random_mac()


@pytest.fixture
def mac_2() -> str:
    return create_random_mac()


@pytest.fixture
def broadcast_mac() -> str:
    return "ff:ff:ff:ff:ff:ff"


@pytest.fixture
def port_1() -> int:
    return randint(1, 60000)


@pytest.fixture
def port_2() -> int:
    return randint(1, 60000)


@pytest.fixture
def port_3() -> int:
    return randint(1, 60000)


@pytest.fixture
def port_4() -> int:
    return randint(1, 60000)


@pytest.fixture
def dns_port() -> int:
    return 53


@pytest.fixture
def http_port() -> int:
    return 80


@pytest.fixture
def icmp_echo_type() -> int:
    return 8


@pytest.fixture
def extracted_fields_from_ethernet_packet() -> List[str]:
    return ["eth.src", "eth.dst"]


@pytest.fixture
def extracted_fields_from_arp_packet(
    extracted_fields_from_ethernet_packet,
) -> List[str]:
    return extracted_fields_from_ethernet_packet + [
        "arp.src.hw_mac",
        "arp.src.proto_ipv4",
        "arp.dst.hw_mac",
        "arp.dst.proto_ipv4",
    ]


@pytest.fixture
def extracted_fields_from_ip_packet(extracted_fields_from_ethernet_packet) -> List[str]:
    return extracted_fields_from_ethernet_packet + ["ip.src", "ip.dst"]


@pytest.fixture
def extracted_fields_from_icmp_packet(extracted_fields_from_ip_packet) -> List[str]:
    return extracted_fields_from_ip_packet + ["icmp.type"]


@pytest.fixture
def extracted_fields_from_tcp_packet(extracted_fields_from_ip_packet) -> List[str]:
    return extracted_fields_from_ip_packet + ["tcp.srcport", "tcp.dstport"]


@pytest.fixture
def extracted_fields_from_udp_packet(extracted_fields_from_ip_packet) -> List[str]:
    return extracted_fields_from_ip_packet + ["udp.srcport", "udp.dstport"]


@pytest.fixture
def extracted_fields_from_dns_packet(extracted_fields_from_udp_packet) -> List[str]:
    return extracted_fields_from_udp_packet + ["dns.qry.name"]


@pytest.fixture
def extracted_fields_from_http_packet(extracted_fields_from_tcp_packet) -> List[str]:
    return extracted_fields_from_tcp_packet + [
        "http.request.method",
        "http.request.uri",
        "http.request.version",
        "http.host",
    ]


@pytest.fixture
def ethernet_packet(mac_1: str, mac_2: str) -> ethernet.Ethernet:
    return ethernet.Ethernet(src_s=mac_1, dst_s=mac_2)


@pytest.fixture
def arp_packet(mac_1: str, broadcast_mac: str, ip_1: str, ip_2: str) -> bytes:
    packet = ethernet.Ethernet(src_s=mac_1, dst_s=broadcast_mac) + arp.ARP(
        sha_s=mac_1, spa_s=ip_1, tha_s=broadcast_mac, tpa_s=ip_2
    )
    return packet.bin()


@pytest.fixture
def icmp_packet(
    ethernet_packet: ethernet.Ethernet, ip_1: str, ip_2: str, icmp_echo_type: int
) -> bytes:
    packet = (
        ethernet_packet
        + ip.IP(src_s=ip_1, dst_s=ip_2, p=ip.IP_PROTO_ICMP)
        + icmp.ICMP(type=icmp_echo_type)
        + icmp.ICMP.Echo()
    )
    return packet.bin()


@pytest.fixture
def tcp_packet(
    ethernet_packet: ethernet.Ethernet, ip_1: str, ip_2: str, port_1: int, port_2: int
) -> bytes:
    packet = (
        ethernet_packet
        + ip.IP(src_s=ip_1, dst_s=ip_2)
        + tcp.TCP(sport=port_1, dport=port_2)
    )
    return packet.bin()


@pytest.fixture
def udp_packet(
    ethernet_packet: ethernet.Ethernet, ip_1: str, ip_2: str, port_3: int, port_4: int
) -> bytes:
    packet = (
        ethernet_packet
        + ip.IP(src_s=ip_1, dst_s=ip_2, p=ip.IP_PROTO_UDP)
        + udp.UDP(sport=port_3, dport=port_4)
    )
    return packet.bin()


@pytest.fixture
def dns_packet(
    ethernet_packet: ethernet.Ethernet,
    ip_1: str,
    ip_2: str,
    port_3: int,
    dns_port: int,
    url_1: str,
) -> bytes:
    packet = (
        ethernet_packet
        + ip.IP(src_s=ip_1, dst_s=ip_2, p=ip.IP_PROTO_UDP)
        + udp.UDP(sport=port_3, dport=dns_port)
    ) + dns.DNS(queries=[dns.DNS.Query(name_s=url_1, type=1, cls=1)])
    return packet.bin()


@pytest.fixture
def http_packet(
    ethernet_packet: ethernet.Ethernet,
    ip_1: str,
    ip_2: str,
    port_1: int,
    http_port: int,
    http_get: HttpDescription,
) -> bytes:
    packet = (
        ethernet_packet
        + ip.IP(src_s=ip_1, dst_s=ip_2)
        + tcp.TCP(sport=port_1, dport=http_port)
        + http.HTTP(
            f'{http_get["http_type"]} {http_get["uri"]} {http_get["version"]}\r\nHost: {http_get["host"]}\r\n\r\n{http_get["body"]}\r\n'.encode()
        )
    )
    return packet.bin()


@pytest.fixture(scope="session")
def marine_instance() -> Marine:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libmarine.so")
    return Marine(path)
