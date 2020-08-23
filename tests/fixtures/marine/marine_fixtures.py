from pathlib import Path
from typing import List, Union

import pytest
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

from marine.marine import Marine
from marine.marine_pool import MarinePool


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
def marine_so_path() -> str:
    path = Path(__file__).parent / "libmarine.so"
    return str(path.resolve())


@pytest.fixture(scope="session")
def epan_auto_reset_count() -> int:
    return 5000


@pytest.fixture(scope="session")
def marine_instance(marine_so_path: str, epan_auto_reset_count: int) -> Marine:
    return Marine(epan_auto_reset_count=epan_auto_reset_count)


@pytest.fixture(scope="session")
def marine_pool_instance(marine_so_path: str, epan_auto_reset_count: int) -> MarinePool:
    with MarinePool(epan_auto_reset_count) as mp:
        yield mp


@pytest.fixture(scope="session", params=["marine_instance", "marine_pool_instance"])
def marine_or_marine_pool(request) -> Union[Marine, MarinePool]:
    return request.getfixturevalue(request.param)
