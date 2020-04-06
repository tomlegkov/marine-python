import struct
from dataclasses import dataclass
from typing import List, Dict, Callable


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


@dataclass(frozen=True)
class Layer3Conversation:
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str


@dataclass
class ConversationGenerator:
    percentage_of_packets: float
    generator: Callable[[Layer3Conversation, int], List[BenchmarkPacket]]


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
