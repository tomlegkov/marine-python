"""
Note: in order to run the tests, you must put libmarine.so next to the marine_fixtures.py file
"""
import pytest
from typing import List, Union, Optional, Dict
from marine import Marine, MarinePool

from pypacker.layer12 import ethernet, arp
from pypacker.layer3 import ip, icmp
from pypacker.layer4 import tcp, udp
from pypacker.layer567 import dns, http, dhcp


# TODO: Add a test for FTP.


def filter_and_parse(
    marine_or_marine_pool: Union[Marine, MarinePool],
    packet: bytes,
    bpf_filter: Optional[str] = None,
    display_filter: Optional[str] = None,
    fields: Optional[List[str]] = None,
):
    return (
        marine_or_marine_pool.filter_and_parse(
            packet, bpf_filter, display_filter, fields
        )
        if isinstance(marine_or_marine_pool, Marine)
        else marine_or_marine_pool.filter_and_parse(
            [packet], bpf_filter, display_filter, fields
        )[0]
    )


def general_filter_and_parse_test(
    marine_or_marine_pool: Union[Marine, MarinePool],
    packet: bytes,
    bpf_filter: Optional[str],
    display_filter: Optional[str],
    expected_passed: bool,
    expected_output: Optional[Dict[str, str]],
):
    expected_fields = list(expected_output.keys()) if expected_output else None
    passed, output = filter_and_parse(
        marine_or_marine_pool, packet, bpf_filter, display_filter, expected_fields
    )

    expected_output = (
        {k: str(v) for k, v in expected_output.items()} if expected_output else None
    )

    assert expected_passed == passed
    assert expected_output == output


def test_arp_packet_filter_and_parse(marine_or_marine_pool: Union[Marine, MarinePool]):
    src_mac = "00:00:00:12:34:ff"
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    src_ip = "21.53.78.255"
    target_ip = "10.0.0.255"
    bpf_filter = "arp"
    display_filter = "arp"
    expected_output = {
        "eth.src": src_mac,
        "eth.dst": broadcast_mac,
        "arp.src.hw_mac": src_mac,
        "arp.src.proto_ipv4": src_ip,
        "arp.dst.hw_mac": broadcast_mac,
        "arp.dst.proto_ipv4": target_ip,
    }
    packet = ethernet.Ethernet(src_s=src_mac, dst_s=broadcast_mac) + arp.ARP(
        sha_s=src_mac, spa_s=src_ip, tha_s=broadcast_mac, tpa_s=target_ip
    )

    general_filter_and_parse_test(
        marine_or_marine_pool=marine_or_marine_pool,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        expected_passed=True,
        expected_output=expected_output,
    )


def test_icmp_packet_filter_and_parse(marine_or_marine_pool: Union[Marine, MarinePool]):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    dst_ip = "10.0.0.255"
    icmp_echo_type = 8
    bpf_filter = "ip"
    display_filter = "icmp"
    expected_output = {
        "eth.src": src_mac,
        "eth.dst": dst_mac,
        "ip.src": src_ip,
        "ip.dst": dst_ip,
        "icmp.type": icmp_echo_type,
    }

    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=dst_ip, p=ip.IP_PROTO_ICMP)
        + icmp.ICMP(type=icmp_echo_type)
        + icmp.ICMP.Echo()
    )

    general_filter_and_parse_test(
        marine_or_marine_pool=marine_or_marine_pool,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        expected_passed=True,
        expected_output=expected_output,
    )


def test_tcp_packet_filter_and_parse(marine_or_marine_pool: Union[Marine, MarinePool]):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    dst_ip = "10.0.0.255"
    src_port = 16424
    dst_port = 41799
    bpf_filter = "ip"
    display_filter = "tcp"
    expected_output = {
        "eth.src": src_mac,
        "eth.dst": dst_mac,
        "ip.src": src_ip,
        "ip.dst": dst_ip,
        "tcp.srcport": src_port,
        "tcp.dstport": dst_port,
    }

    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=dst_ip)
        + tcp.TCP(sport=src_port, dport=dst_port)
    )

    general_filter_and_parse_test(
        marine_or_marine_pool=marine_or_marine_pool,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        expected_passed=True,
        expected_output=expected_output,
    )


def test_dns_packet_filter_and_parse(marine_or_marine_pool: Union[Marine, MarinePool]):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    dst_ip = "10.0.0.255"
    src_port = 16424
    dst_port = 53
    bpf_filter = "ip"
    display_filter = "dns"
    domain_name = "www.testwebsite.com"
    expected_output = {
        "eth.src": src_mac,
        "eth.dst": dst_mac,
        "ip.src": src_ip,
        "ip.dst": dst_ip,
        "udp.srcport": src_port,
        "udp.dstport": dst_port,
        "dns.qry.name": domain_name,
    }

    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=dst_ip, p=ip.IP_PROTO_UDP)
        + udp.UDP(sport=src_port, dport=dst_port)
        + dns.DNS(queries=[dns.DNS.Query(name_s=domain_name, type=1, cls=1)])
    )

    general_filter_and_parse_test(
        marine_or_marine_pool=marine_or_marine_pool,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        expected_passed=True,
        expected_output=expected_output,
    )


def test_dhcp_packet_filter_and_parse(marine_or_marine_pool: Union[Marine, MarinePool]):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    given_ip = "10.0.0.255"
    broadcast_ip = "255.255.255.255"
    src_port = 16424
    dst_port = 68
    bpf_filter = "ip"
    display_filter = "dhcp"
    expected_output = {
        "eth.src": src_mac,
        "eth.dst": dst_mac,
        "ip.src": src_ip,
        "ip.dst": broadcast_ip,
        "udp.srcport": src_port,
        "udp.dstport": dst_port,
        "dhcp.ip.your": given_ip,
        "dhcp.option.dhcp_server_id": src_ip,
    }

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
        marine_or_marine_pool=marine_or_marine_pool,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        expected_passed=True,
        expected_output=expected_output,
    )


def test_http_packet_filter_and_parse(marine_or_marine_pool: Union[Marine, MarinePool]):
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
    expected_output = {
        "eth.src": src_mac,
        "eth.dst": dst_mac,
        "ip.src": src_ip,
        "ip.dst": dst_ip,
        "tcp.srcport": src_port,
        "tcp.dstport": dst_port,
        "http.request.method": http_type,
        "http.request.uri": uri,
        "http.request.version": version,
        "http.host": domain_name,
    }
    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=dst_ip)
        + tcp.TCP(sport=src_port, dport=dst_port)
        + http.HTTP(
            f"{http_type} {uri} {version}\r\nHost: {domain_name}\r\n\r\n{body}\r\n".encode()
        )
    )

    general_filter_and_parse_test(
        marine_or_marine_pool=marine_or_marine_pool,
        packet=packet.bin(),
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        expected_passed=True,
        expected_output=expected_output,
    )


def test_filter_and_parse_without_filters(
    marine_or_marine_pool: Union[Marine, MarinePool]
):
    src_mac = "00:00:00:12:34:ff"
    dst_mac = "00:00:00:ff:00:1e"
    src_ip = "21.53.78.255"
    dst_ip = "10.0.0.255"
    src_port = 16424
    dst_port = 41799
    expected_output = {
        "eth.src": src_mac,
        "eth.dst": dst_mac,
        "ip.src": src_ip,
        "ip.dst": dst_ip,
        "tcp.srcport": src_port,
        "tcp.dstport": dst_port,
    }

    packet = (
        ethernet.Ethernet(src_s=src_mac, dst_s=dst_mac)
        + ip.IP(src_s=src_ip, dst_s=dst_ip)
        + tcp.TCP(sport=src_port, dport=dst_port)
    )

    general_filter_and_parse_test(
        marine_or_marine_pool=marine_or_marine_pool,
        packet=packet.bin(),
        bpf_filter=None,
        display_filter=None,
        expected_passed=True,
        expected_output=expected_output,
    )


def test_filter_and_parse_without_fields(
    marine_or_marine_pool: Union[Marine, MarinePool], tcp_packet: bytes
):
    general_filter_and_parse_test(
        marine_or_marine_pool=marine_or_marine_pool,
        packet=tcp_packet,
        bpf_filter="ip",
        display_filter="tcp",
        expected_passed=True,
        expected_output=None,
    )


def test_preferences_change_effect_while_running(
    marine_or_marine_pool: Union[Marine, MarinePool]
):
    packet = (
        ethernet.Ethernet(src_s="00:00:00:12:34:ff", dst_s="00:00:00:ff:00:1e")
        + ip.IP(src_s="21.53.78.255", dst_s="10.0.0.255")
        + tcp.TCP(sport=16424, dport=41799, sum=49058)
    )

    marine_or_marine_pool.set_preferences(['tcp.check_checksum:true'])
    # tcp.checksum.status == 1 mean it's a valid checksum
    expected_output = {
        "tcp.checksum.status": "1",
    }
    general_filter_and_parse_test(
        marine_or_marine_pool=marine_or_marine_pool,
        packet=packet.bin(),
        bpf_filter=None,
        display_filter=None,
        expected_passed=True,
        expected_output=expected_output,
    )

    marine_or_marine_pool.set_preferences(['tcp.check_checksum:false'])
    # tcp.checksum.status == 2 mean unverified checksum
    expected_output = {
        "tcp.checksum.status": "2"
    }
    general_filter_and_parse_test(
        marine_or_marine_pool=marine_or_marine_pool,
        packet=packet.bin(),
        bpf_filter=None,
        display_filter=None,
        expected_passed=True,
        expected_output=expected_output,
    )


def test_packet_doesnt_pass_filter_because_of_bpf(
    marine_instance: Marine,
    tcp_packet: bytes,
    extracted_fields_from_tcp_packet: List[str],
):
    passed, output = filter_and_parse(
        marine_instance, tcp_packet, "arp", fields=extracted_fields_from_tcp_packet
    )

    assert not passed
    assert output is None


def test_packet_doesnt_pass_filter_because_of_display_filter(
    marine_instance: Marine,
    tcp_packet: bytes,
    extracted_fields_from_tcp_packet: List[str],
):
    passed, output = filter_and_parse(
        marine_instance,
        tcp_packet,
        display_filter="udp",
        fields=extracted_fields_from_tcp_packet,
    )

    assert not passed
    assert output is None


def test_illegal_bpf_in_filter_and_parse(
    marine_or_marine_pool: Union[Marine, MarinePool], tcp_packet: bytes
):
    with pytest.raises(ValueError, match="Failed compiling the BPF"):
        filter_and_parse(
            marine_or_marine_pool, tcp_packet, bpf_filter="what is this bpf?"
        )


def test_illegal_display_filter_in_filter_and_parse(
    marine_or_marine_pool: Union[Marine, MarinePool], tcp_packet: bytes
):
    with pytest.raises(ValueError, match="neither a field nor a protocol name"):
        filter_and_parse(
            marine_or_marine_pool, tcp_packet, display_filter="illegal_filter"
        )


def test_illegal_fields_in_filter_and_parse(
    marine_or_marine_pool: Union[Marine, MarinePool], tcp_packet: bytes
):
    with pytest.raises(ValueError) as excinfo:
        filter_and_parse(
            marine_or_marine_pool,
            tcp_packet,
            fields=["illegal_field_1", "illegal_field_2", "ip.src"],
        )
    err_msg = str(excinfo)

    assert "illegal_field_1" in err_msg
    assert "illegal_field_2" in err_msg
    assert "ip.src" not in err_msg


def test_filter_and_parse_with_no_parameters(
    marine_or_marine_pool: Union[Marine, MarinePool], tcp_packet: bytes
):
    with pytest.raises(ValueError, match="must be passed"):
        filter_and_parse(marine_or_marine_pool, tcp_packet)


def test_validate_bpf_success(marine_instance: Union[Marine, MarinePool]):
    assert marine_instance.validate_bpf("arp")


def test_validate_bpf_failure(marine_instance: Union[Marine, MarinePool]):
    assert not marine_instance.validate_bpf("what is this bpf?")


def test_validate_display_filter_success(marine_instance: Marine):
    assert marine_instance.validate_display_filter("tcp")


def test_validate_display_filter_failure(marine_instance: Marine):
    assert not marine_instance.validate_display_filter("illegal_filter")


def test_get_epan_auto_reset_count(marine_instance: Marine, epan_auto_reset_count: int):
    assert marine_instance.epan_auto_reset_count == epan_auto_reset_count


def test_set_epan_auto_reset_count(marine_instance: Marine):
    SOME_VALUE = 1
    assert marine_instance.epan_auto_reset_count != SOME_VALUE
    marine_instance.epan_auto_reset_count = SOME_VALUE
    assert marine_instance.epan_auto_reset_count == SOME_VALUE
