import os
from typing import List

import pytest
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

from marine import Marine


@pytest.fixture
def extracted_fields_from_tcp_packet() -> List[str]:
    return ["eth.src", "eth.dst", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport"]


@pytest.fixture
def tcp_packet() -> bytes:
    packet = (
        ethernet.Ethernet(src_s="00:00:00:12:34:ff", dst_s="00:00:00:ff:00:1e")
        + ip.IP(src_s="10.0.0.255", dst_s="21.53.78.255")
        + tcp.TCP(sport=16424, dport=41799)
    )
    return packet.bin()


@pytest.fixture(scope="session")
def libmarine_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "libmarine.so")


@pytest.fixture(scope="session")
def epan_auto_reset_count() -> int:
    return 5000


@pytest.fixture(scope="session")
def marine_instance(libmarine_path: str, epan_auto_reset_count: int) -> object:
    return Marine(libmarine_path, epan_auto_reset_count=epan_auto_reset_count)
