import struct
from dataclasses import dataclass, field
from random import randint
from typing import List, Dict, Callable, Set, Tuple


@dataclass
class BenchmarkPacket:
    packet: bytes
    good_bpf: str
    good_display_filter: str
    # TODO: add bad_bpf and bad_display_filter to drop some packets
    # bad_bpf: str
    # bad_display_filter: str
    fields_to_extract: List[str]
    expected_parse_result: Dict[str, str]


@dataclass
class IpPair:
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    _ports: Set[int] = field(default_factory=set)

    def _generate_port(self) -> int:
        port = randint(10000, 60000)
        while port in self._ports:
            port = randint(10000, 60000)
        self._ports.add(port)
        return port

    def generate_port_pair(self) -> Tuple[int, int]:
        return self._generate_port(), self._generate_port()


@dataclass
class ConversationGenerator:
    percentage_of_packets: float
    generator: Callable[[IpPair, int], List[BenchmarkPacket]]


def write_cap(file_path: str, packets: List[bytes]):
    """
    This is a good util for debugging, which is why I'm keeping it here.
    """
    PCAP_HEADER = bytes.fromhex("D4C3B2A10200040000000000000000000000040001000000")
    data = b""
    for packet in packets:
        data += struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet

    with open(file_path, "wb") as f:
        f.write(PCAP_HEADER + data)
