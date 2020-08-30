from .marine import Marine
from typing import Optional, List, Dict, Tuple

marine_instance = None


def init_instance(epan_auto_reset_count: Optional[int] = None) -> Marine:
    global marine_instance

    if marine_instance is None:
        marine_instance = Marine(epan_auto_reset_count)
    return marine_instance


def filter_packet(
    packet: bytes,
    bpf: Optional[str] = None,
    display_filter: Optional[str] = None,
    encapsulation_type: Optional[int] = None,
) -> bool:
    """
    Filters a packet with BPF and a Wireshark-style display filter.
    At least one form of filtering is required.
    By default the packet is parsed as an ethernet packet,
    to view other possible encapsulation values view encap_consts.
    """
    return init_instance().filter(
        packet=packet,
        bpf=bpf,
        display_filter=display_filter,
        encapsulation_type=encapsulation_type,
    )


def parse_packet(
    packet: bytes,
    fields: Optional[List[str]] = None,
    macros: Optional[Dict[str, List[str]]] = None,
    encapsulation_type: Optional[int] = None,
) -> Dict[str, Optional[str]]:
    """
    Parses the given fields from the packet. Fields have the same name as specified for Wireshark.
    If you want to add a custom field, you need to have the required dissector in your Wireshark plugins folder.
    Fields that are not available in the packet will be returned as "".
    Macros can be used to expand a field - Example macro format: {"macro.ip.src" : ["ip.src", "ipv6.src"]}.
    By default the packet is parsed as an ethernet packet,
    to view other possible encapsulation values view encap_consts.
    """
    return init_instance().parse(
        packet=packet,
        fields=fields,
        encapsulation_type=encapsulation_type,
        macros=macros,
    )


def filter_and_parse_packet(
    packet: bytes,
    bpf: Optional[List[str]] = None,
    display_filter: Optional[str] = None,
    fields: Optional[List[str]] = None,
    macros: Optional[Dict[str, List[str]]] = None,
    encapsulation_type: Optional[int] = None,
) -> Tuple[bool, Dict[str, Optional[str]]]:
    """
    Filters a packet with BPF and a Wireshark-style display filter.
    If the filter passes, parses the packet according to the fields.
    Fields have the same name as specified for Wireshark.
    Either the bpf, display filter or fields must be not None.
    If the packet does not pass the filter, or fields is None, result fields will be None as well.
    Fields that are not available in the packet will be returned as "".
    If you want to add a custom field, you need to have the required dissector in your Wireshark plugins folder.
    By default the packet is parsed as an ethernet packet,
    to view other possible encapsulation values view encap_consts.
    """
    return init_instance().filter_and_parse(
        packet=packet,
        bpf=bpf,
        display_filter=display_filter,
        fields=fields,
        macros=macros,
        encapsulation_type=encapsulation_type,
    )


def validate_bpf(
    bpf: str,
    encapsulation_type: Optional[int] = None,
) -> bool:
    """
    Validates the given BPF.
    By default the BPF is parsed with ethernet encapsulation,
    to view other possible encapsulation values view encap_consts.
    """
    return init_instance().validate_bpf(bpf=bpf, encapsulation_type=encapsulation_type)


def validate_display_filter(display_filter: str) -> bool:
    """
    Validates the given display filter.
    """
    return init_instance().validate_display_filter(display_filter=display_filter)


def validate_fields(
    fields: List[str],
    macros: Optional[Dict[str, List[str]]] = None,
) -> bool:
    """
    Validates the given fields. Fields have the same name as specified for Wireshark.
    If you want to add a custom field, you need to have the required dissector in your Wireshark plugins folder.
    Macros can be used to expand a field - Example macro format: {"macro.ip.src" : ["ip.src", "ipv6.src"]}.
    """
    return init_instance().validate_fields(fields=fields, macros=macros)


def get_marine() -> Marine:
    """
    Gets the used marine object.
    """
    return init_instance()
