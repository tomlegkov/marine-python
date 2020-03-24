"""
Note: in order to run the tests, you must put libmarine.so next to the marine_fixtures.py file
"""
import pytest
from pytest_lazyfixture import lazy_fixture
from parametrization import Parametrization
from typing import List, Dict, Union
from marine import Marine


# TODO: Add a test for FTP.


@Parametrization.parameters(
    "packet",
    "fields_expected_fixture_name",
    "extracted_fields_from_packet",
    "bpf_filter",
    "display_filter",
)
@Parametrization.case(
    name="ARP packet",
    packet=lazy_fixture("arp_packet"),
    fields_expected_fixture_name=[
        "mac_1",
        "broadcast_mac",
        "mac_1",
        "ip_1",
        "broadcast_mac",
        "ip_2",
    ],
    extracted_fields_from_packet=lazy_fixture("extracted_fields_from_arp_packet"),
    bpf_filter="arp",
    display_filter="arp",
)
@Parametrization.case(
    name="ICMP packet",
    packet=lazy_fixture("icmp_packet"),
    fields_expected_fixture_name=["mac_1", "mac_2", "ip_1", "ip_2", "icmp_echo_type"],
    extracted_fields_from_packet=lazy_fixture("extracted_fields_from_icmp_packet"),
    bpf_filter="ip",
    display_filter="icmp",
)
@Parametrization.case(
    name="TCP packet",
    packet=lazy_fixture("tcp_packet"),
    fields_expected_fixture_name=["mac_1", "mac_2", "ip_1", "ip_2", "port_1", "port_2"],
    extracted_fields_from_packet=lazy_fixture("extracted_fields_from_tcp_packet"),
    bpf_filter="ip",
    display_filter="tcp",
)
@Parametrization.case(
    name="DNS packet",
    packet=lazy_fixture("dns_packet"),
    fields_expected_fixture_name=[
        "mac_1",
        "mac_2",
        "ip_1",
        "ip_2",
        "port_3",
        "dns_port",
        "url_1",
    ],
    extracted_fields_from_packet=lazy_fixture("extracted_fields_from_dns_packet"),
    bpf_filter="ip",
    display_filter="dns",
)
@Parametrization.case(
    name="DHCP packet",
    packet=lazy_fixture("dhcp_packet"),
    fields_expected_fixture_name=[
        "mac_1",
        "mac_2",
        "ip_1",
        "broadcast_ip",
        "port_3",
        "dhcp_port",
        "ip_2",
        "ip_1",
    ],
    extracted_fields_from_packet=lazy_fixture("extracted_fields_from_dhcp_packet"),
    bpf_filter="ip",
    display_filter="dhcp",
)
@Parametrization.case(
    name="HTTP packet",
    packet=lazy_fixture("http_packet"),
    fields_expected_fixture_name=[
        "mac_1",
        "mac_2",
        "ip_1",
        "ip_2",
        "port_1",
        "http_port",
        "http_type",
        "http_uri",
        "http_version",
        "url_1",
    ],
    extracted_fields_from_packet=lazy_fixture("extracted_fields_from_http_packet"),
    bpf_filter="ip",
    display_filter="http",
)
def test_packet_filter_and_parse(
    request,
    marine_instance: Marine,
    packet: bytes,
    fields_expected_fixture_name: List[Union[str, int]],
    extracted_fields_from_packet: List[str],
    bpf_filter: str,
    display_filter: str,
):
    expected = dict(
        zip(
            extracted_fields_from_packet,
            map(
                lambda x: str(request.getfixturevalue(x)), fields_expected_fixture_name
            ),
        )
    )
    passed, output = marine_instance.filter_and_parse(
        packet, bpf_filter, display_filter, extracted_fields_from_packet
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
