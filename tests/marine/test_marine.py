"""
Note: in order to run the tests, you must put libmarine.so next to the marine_fixtures.py file
"""
import pytest
from typing import List, Dict
from marine import Marine


def test_arp_filter_and_parse(
    marine_instance: Marine,
    arp_packet: bytes,
    mac_1: str,
    broadcast_mac: str,
    ip_1: str,
    ip_2: str,
    extracted_fields_from_arp_packet: List[str],
):
    """
    Testing layer 2 protocol parsing.
    """
    expected = dict(
        zip(
            extracted_fields_from_arp_packet,
            map(str, [mac_1, broadcast_mac, mac_1, ip_1, broadcast_mac, ip_2]),
        )
    )
    passed, output = marine_instance.filter_and_parse(
        arp_packet, "arp", "arp", extracted_fields_from_arp_packet
    )

    assert passed
    assert expected == output


def test_icmp_filter_and_parse(
    marine_instance: Marine,
    icmp_packet: bytes,
    mac_1: str,
    mac_2: str,
    ip_1: str,
    ip_2: str,
    icmp_echo_type: int,
    extracted_fields_from_icmp_packet: List[str],
):
    """
    Testing layer 3 protocol parsing.
    """
    expected = dict(
        zip(
            extracted_fields_from_icmp_packet,
            map(str, [mac_1, mac_2, ip_1, ip_2, icmp_echo_type]),
        )
    )

    passed, output = marine_instance.filter_and_parse(
        icmp_packet, "ip", "icmp", extracted_fields_from_icmp_packet
    )

    assert passed
    assert expected == output


def test_tcp_filter_and_parse(
    marine_instance: Marine,
    tcp_packet: bytes,
    mac_1: str,
    mac_2: str,
    ip_1: str,
    ip_2: str,
    port_1: int,
    port_2: int,
    extracted_fields_from_tcp_packet: List[str],
):
    """
    Testing layer 4 protocol parsing.
    """
    expected = dict(
        zip(
            extracted_fields_from_tcp_packet,
            map(str, [mac_1, mac_2, ip_1, ip_2, port_1, port_2]),
        )
    )

    passed, output = marine_instance.filter_and_parse(
        tcp_packet, "ip", "tcp", extracted_fields_from_tcp_packet
    )

    assert passed
    assert expected == output


def test_dns_filter_and_parse(
    marine_instance: Marine,
    dns_packet: bytes,
    mac_1: str,
    mac_2: str,
    ip_1: str,
    ip_2: str,
    port_3: int,
    dns_port: int,
    url_1: str,
    extracted_fields_from_dns_packet: List[str],
):
    """
    Testing a layer 567 protocol, and dns specificaly to check query parsing.
    """
    expected = dict(
        zip(
            extracted_fields_from_dns_packet,
            map(str, [mac_1, mac_2, ip_1, ip_2, port_3, dns_port, url_1]),
        )
    )
    passed, output = marine_instance.filter_and_parse(
        dns_packet, "ip", "dns", extracted_fields_from_dns_packet
    )

    assert passed
    assert expected == output


def test_http_filter_and_parse(
    marine_instance: Marine,
    http_packet: bytes,
    mac_1: str,
    mac_2: str,
    ip_1: str,
    ip_2: str,
    port_1: int,
    http_port: int,
    http_get: Dict[str, str],
    extracted_fields_from_http_packet: List[str],
):
    """
    Testing a layer 567 protocol, and http speificaly for text fields.
    """
    expected = dict(
        zip(
            extracted_fields_from_http_packet,
            map(
                str,
                [
                    mac_1,
                    mac_2,
                    ip_1,
                    ip_2,
                    port_1,
                    http_port,
                    http_get["http_type"],
                    http_get["uri"],
                    http_get["version"],
                    http_get["host"],
                ],
            ),
        )
    )
    passed, output = marine_instance.filter_and_parse(
        http_packet, "ip", "http", extracted_fields_from_http_packet
    )

    assert passed
    assert expected == output


def test_filter_and_parse_without_fields(marine_instance: Marine, tcp_packet: bytes):
    passed, output = marine_instance.filter_and_parse(tcp_packet, "ip", "tcp")

    assert passed
    assert output is None


def test_filter_and_parse_without_filters(
    marine_instance: Marine,
    tcp_packet: bytes,
    mac_1: str,
    mac_2: str,
    ip_1: str,
    ip_2: str,
    port_1: int,
    port_2: int,
    extracted_fields_from_tcp_packet: List[str],
):
    expected = dict(
        zip(
            extracted_fields_from_tcp_packet,
            map(str, [mac_1, mac_2, ip_1, ip_2, port_1, port_2]),
        )
    )
    passed, output = marine_instance.filter_and_parse(
        tcp_packet, fields=extracted_fields_from_tcp_packet
    )

    assert passed
    assert expected == output


def test_packet_doesnt_pass_filter_because_of_bfp(
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
    with pytest.raises(ValueError) as excinfo:
        marine_instance.filter_and_parse(tcp_packet, bpf="what is this bpf?")
    assert "Failed compiling the BPF" in str(excinfo)


def test_illegal_display_filter_in_filter_and_parse(
    marine_instance: Marine, tcp_packet: bytes
):
    with pytest.raises(ValueError) as excinfo:
        marine_instance.filter_and_parse(tcp_packet, display_filter="illegal_filter")
    assert "neither a field nor a protocol name" in str(excinfo)


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
    with pytest.raises(ValueError) as excinfo:
        marine_instance.filter_and_parse(tcp_packet)
    assert "must be passed" in str(excinfo)
