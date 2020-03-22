"""
Note: in order to run the tests, you must put libmarine.so next to the marine_fixtures.py file
"""
import pytest


# TODO: test more common protocols: ARP, ICMP, HTTP, etc.


def test_arp_filter_and_parse(marine_instance, arp_packet, mac_1, broadcast_mac, ip_1, ip_2,
                              extracted_fields_from_arp_packet):
    expected = dict(zip(extracted_fields_from_arp_packet, map(str, [mac_1, broadcast_mac, mac_1, ip_1, broadcast_mac, ip_2])))
    passed, output = marine_instance.filter_and_parse(arp_packet, 'arp', 'arp', extracted_fields_from_arp_packet)

    assert passed
    assert expected == output


def test_icmp_filter_and_parse(marine_instance, icmp_packet, mac_1, mac_2, ip_1, ip_2, icmp_type,
                               extracted_fields_from_icmp_packet):
    expected = dict(zip(extracted_fields_from_icmp_packet, map(str, [mac_1, mac_2, ip_1, ip_2, icmp_type])))

    passed, output = marine_instance.filter_and_parse(icmp_packet, 'ip', 'icmp', extracted_fields_from_icmp_packet)

    assert passed
    assert expected == output


def test_tcp_filter_and_parse(marine_instance, tcp_packet, mac_1, mac_2, ip_1, ip_2, port_1, port_2,
                              extracted_fields_from_tcp_packet):
    expected = dict(zip(extracted_fields_from_tcp_packet, map(str, [mac_1, mac_2, ip_1, ip_2, port_1, port_2])))

    passed, output = marine_instance.filter_and_parse(tcp_packet, 'ip', 'tcp', extracted_fields_from_tcp_packet)

    assert passed
    assert expected == output


def test_udp_filter_and_parse(marine_instance, udp_packet, mac_1, mac_2, ip_1, ip_2, port_3, port_4,
                              extracted_fields_from_udp_packet):
    expected = dict(zip(extracted_fields_from_udp_packet, map(str, [mac_1, mac_2, ip_1, ip_2, port_3, port_4])))
    passed, output = marine_instance.filter_and_parse(udp_packet, 'ip', 'udp', extracted_fields_from_udp_packet)

    assert passed
    assert expected == output


def test_dns_filter_and_parse(marine_instance, dns_packet, mac_1, mac_2, ip_1, ip_2, port_3, port_4,
                              byte_field_1, byte_field_2, url_1, extracted_fields_from_dns_packet):
    expected = dict(zip(extracted_fields_from_dns_packet, map(str, 
                [mac_1, mac_2, ip_1, ip_2, port_3, port_4, byte_field_1, byte_field_2, url_1])))
    passed, output = marine_instance.filter_and_parse(dns_packet, 'ip', 'dns', extracted_fields_from_dns_packet)

    assert passed
    assert expected == output



def test_filter_and_parse_without_fields(marine_instance, tcp_packet):
    passed, output = marine_instance.filter_and_parse(tcp_packet, 'ip', 'tcp')

    assert passed
    assert output is None


def test_filter_and_parse_without_filters(marine_instance, tcp_packet, mac_1, mac_2, ip_1, ip_2, port_1, port_2,
                                          extracted_fields_from_tcp_packet):
    expected = dict(zip(extracted_fields_from_tcp_packet, map(str, [mac_1, mac_2, ip_1, ip_2, port_1, port_2])))
    passed, output = marine_instance.filter_and_parse(tcp_packet, fields=extracted_fields_from_tcp_packet)

    assert passed
    assert expected == output


def test_packet_doesnt_pass_filter_because_of_bfp(marine_instance, tcp_packet, extracted_fields_from_tcp_packet):
    passed, output = marine_instance.filter_and_parse(tcp_packet, 'arp', fields=extracted_fields_from_tcp_packet)

    assert not passed
    assert output is None


def test_packet_doesnt_pass_filter_because_of_display_filter(marine_instance, tcp_packet,
                                                             extracted_fields_from_tcp_packet):
    passed, output = marine_instance.filter_and_parse(tcp_packet, display_filter='udp',
                                                      fields=extracted_fields_from_tcp_packet)

    assert not passed
    assert output is None


def test_illegal_bpf_in_filter_and_parse(marine_instance, tcp_packet):
    with pytest.raises(ValueError) as excinfo:
        marine_instance.filter_and_parse(tcp_packet, bpf='what is this bpf?')
    assert 'Failed compiling the BPF' in str(excinfo)


def test_illegal_display_filter_in_filter_and_parse(marine_instance, tcp_packet):
    with pytest.raises(ValueError) as excinfo:
        marine_instance.filter_and_parse(tcp_packet, display_filter='illegal_filter')
    assert 'neither a field nor a protocol name' in str(excinfo)


def test_illegal_fields_in_filter_and_parse(marine_instance, tcp_packet):
    with pytest.raises(ValueError) as excinfo:
        marine_instance.filter_and_parse(tcp_packet, fields=['illegal_field_1', 'illegal_field_2', 'ip.src'])
    err_msg = str(excinfo)

    assert 'illegal_field_1' in err_msg
    assert 'illegal_field_2' in err_msg
    assert 'ip.src' not in err_msg


def test_filter_and_parse_with_no_parameters(marine_instance, tcp_packet):
    with pytest.raises(ValueError) as excinfo:
        marine_instance.filter_and_parse(tcp_packet)
    assert 'must be passed' in str(excinfo)
