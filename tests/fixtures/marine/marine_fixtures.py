import os
from ipaddress import IPv4Address
from random import getrandbits, randint

import pytest
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp, udp

from marine import Marine


def create_random_ip() -> str:
    return str(IPv4Address(getrandbits(32)))


def create_random_mac() -> str:
    return '00:00:00:%02x:%02x:%02x' % (randint(0, 255), randint(0, 255), randint(0, 255))


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
def extracted_fields_from_ip_packet():
    return ['eth.src', 'eth.dst', 'ip.src', 'ip.dst']


@pytest.fixture
def extracted_fields_from_tcp_packet(extracted_fields_from_ip_packet):
    return extracted_fields_from_ip_packet + ['tcp.srcport', 'tcp.dstport']


@pytest.fixture
def extracted_fields_from_udp_packet(extracted_fields_from_ip_packet):
    return extracted_fields_from_ip_packet + ['udp.srcport', 'udp.dstport']


@pytest.fixture
def tcp_packet(mac_1, mac_2, ip_1, ip_2, port_1, port_2):
    packet = (ethernet.Ethernet(src_s=mac_1, dst_s=mac_2) + ip.IP(src_s=ip_1, dst_s=ip_2)
              + tcp.TCP(sport=port_1, dport=port_2))
    return packet.bin()


@pytest.fixture
def udp_packet(mac_1, mac_2, ip_1, ip_2, port_3, port_4):
    packet = (ethernet.Ethernet(src_s=mac_1, dst_s=mac_2) + ip.IP(src_s=ip_1, dst_s=ip_2, p=ip.IP_PROTO_UDP)
              + udp.UDP(sport=port_3, dport=port_4))
    return packet.bin()


@pytest.fixture(scope='session')
def marine_instance():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libmarine.so')
    return Marine(path)
