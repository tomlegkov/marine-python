import os
from ipaddress import IPv4Address
from random import getrandbits, randint, choices
import string

import pytest
from pypacker.layer12 import ethernet, arp
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import tcp, udp
from pypacker.layer567 import dns

from marine import Marine


def create_random_ip() -> str:
    return str(IPv4Address(getrandbits(32)))


def create_random_mac() -> str:
    return '00:00:00:%02x:%02x:%02x' % (randint(0, 255), randint(0, 255), randint(0, 255))


def create_random_url(length: int) -> str:
    return 'www.%s.com' % (''.join(choices(string.ascii_lowercase, k=length)))


@pytest.fixture
def url_1():
    return create_random_url(8)


@pytest.fixture
def ip_1():
    return create_random_ip()


@pytest.fixture
def ip_2():
    return create_random_ip()


@pytest.fixture
def mac_1():
    return create_random_mac()


@pytest.fixture
def mac_2():
    return create_random_mac()


@pytest.fixture
def broadcast_mac():
    return 'ff:ff:ff:ff:ff:ff'


@pytest.fixture
def port_1():
    return randint(1, 60000)


@pytest.fixture
def port_2():
    return randint(1, 60000)


@pytest.fixture
def port_3():
    return randint(1, 60000)


@pytest.fixture
def port_4():
    return randint(1, 60000)


@pytest.fixture
def icmp_type():
    return 8


@pytest.fixture
def byte_field_1():
    return randint(1, 255)


@pytest.fixture
def byte_field_2():
    return 1


@pytest.fixture
def extracted_fields_from_ethernet_packet():
    return ['eth.src', 'eth.dst']


@pytest.fixture
def extracted_fields_from_arp_packet(extracted_fields_from_ethernet_packet):
    return extracted_fields_from_ethernet_packet + ['arp.src.hw_mac', 'arp.src.proto_ipv4', 'arp.dst.hw_mac', 'arp.dst.proto_ipv4']


@pytest.fixture
def extracted_fields_from_ip_packet(extracted_fields_from_ethernet_packet):
    return extracted_fields_from_ethernet_packet + ['ip.src', 'ip.dst']


@pytest.fixture
def extracted_fields_from_icmp_packet(extracted_fields_from_ip_packet):
    return extracted_fields_from_ip_packet + ['icmp.type']


@pytest.fixture
def extracted_fields_from_tcp_packet(extracted_fields_from_ip_packet):
    return extracted_fields_from_ip_packet + ['tcp.srcport', 'tcp.dstport']


@pytest.fixture
def extracted_fields_from_udp_packet(extracted_fields_from_ip_packet):
    return extracted_fields_from_ip_packet + ['udp.srcport', 'udp.dstport']


@pytest.fixture
def extracted_fields_from_dns_packet(extracted_fields_from_udp_packet):
    return extracted_fields_from_udp_packet + ['dns.id', 'dns.count.queries', 'dns.qry.name']


@pytest.fixture
def arp_packet(mac_1, broadcast_mac, ip_1, ip_2):
    packet = (ethernet.Ethernet(src_s=mac_1, dst_s=broadcast_mac)
              + arp.ARP(sha_s=mac_1, spa_s=ip_1, tha_s=broadcast_mac, tpa_s=ip_2))
    return packet.bin()


@pytest.fixture
def icmp_packet(mac_1, mac_2, ip_1, ip_2, icmp_type):
    packet = (ethernet.Ethernet(src_s=mac_1, dst_s=mac_2) + ip.IP(src_s=ip_1, dst_s=ip_2, p=ip.IP_PROTO_ICMP)
              + icmp.ICMP(type=icmp_type)) + icmp.ICMP.Echo(id=1, ts=123456789, body_bytes=b'data')
    return packet.bin()


@pytest.fixture
def tcp_packet(mac_1, mac_2, ip_1, ip_2, port_1, port_2):
    packet = (ethernet.Ethernet(src_s=mac_1, dst_s=mac_2) + ip.IP(src_s=ip_1, dst_s=ip_2)
              + tcp.TCP(sport=port_1, dport=port_2))
    return packet.bin()


@pytest.fixture
def pypacker_udp_packet(mac_1, mac_2, ip_1, ip_2, port_3, port_4):
    packet = (ethernet.Ethernet(src_s=mac_1, dst_s=mac_2) + ip.IP(src_s=ip_1, dst_s=ip_2, p=ip.IP_PROTO_UDP)
              + udp.UDP(sport=port_3, dport=53))
    return packet


@pytest.fixture
def udp_packet(pypacker_udp_packet):
    return pypacker_udp_packet.bin()


@pytest.fixture
def dns_packet(pypacker_udp_packet, byte_field_1, byte_field_2, url_1):
    packet = pypacker_udp_packet + dns.DNS(id=byte_field_1, questions_count=byte_field_2, flags=0x0100,
              queries=[dns.DNS.Query(name_s=url_1, type=1, cls=1)])
    print(url_1)
    return packet.bin()


@pytest.fixture(scope='session')
def marine_instance():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libmarine.so')
    return Marine(path)
