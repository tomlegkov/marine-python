from .marine import Marine
from . import encap_consts
from typing import Optional, List, Dict, Tuple
import sys
import os.path

marine_instance = {}


def init_instance(
    lib_path: Optional[str] = None, epan_auto_reset_count: Optional[int] = None
) -> Marine:
    global marine_instance

    if lib_path is None:
        lib_path = os.path.join(sys.prefix, "lib64", "libmarine.so")

    if lib_path in marine_instance:
        return marine_instance[lib_path]
    else:
        if (
            len(marine_instance) > 0
        ):  # TODO: support creation of multiple marines (issue #20)
            raise ValueError("Only one path to marine is supported per process.")

        marine_instance[lib_path] = Marine(lib_path, epan_auto_reset_count)
        return marine_instance[lib_path]


def filter_packet(
    packet: bytes,
    bpf: Optional[str] = None,
    display_filter: Optional[str] = None,
    encapsulation_type: int = encap_consts.ENCAP_ETHERNET,
    lib_path: Optional[str] = None,
) -> bool:
    """
    Filters a packet with BPF and a Wireshark-style display filter.
    At least one form of filtering is required.
    By default the packet is parsed as an ethernet packet,
    to view other possible encapsulation values view encap_consts.
    If not specified marine path is set to /user/lib64/libmarine.so .
    """
    return init_instance(lib_path).filter(
        packet=packet,
        bpf=bpf,
        display_filter=display_filter,
        encapsulation_type=encapsulation_type,
    )


def parse_packet(
    packet: bytes,
    fields: Optional[List[str]] = None,
    macros: Optional[Dict[str, List[str]]] = None,
    encapsulation_type: int = encap_consts.ENCAP_ETHERNET,
    lib_path: Optional[str] = None,
) -> Dict[str, str]:
    """
    Parses the given fields from the packet. Fields have the same name as specified for Wireshark.
    If you want to add a custom field, you need to have the required dissector in your Wireshark plugins folder.
    Fields that are not available in the packet will be returned as "".
    Macros can be used to expand a field - Example macro format: {"macro.ip.src" : ["ip.src", "ipv6.src"]}.
    By default the packet is parsed as an ethernet packet,
    to view other possible encapsulation values view encap_consts.
    If not specified marine path is set to /user/lib64/libmarine.so .
    """
    return init_instance(lib_path).parse(
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
    encapsulation_type: int = encap_consts.ENCAP_ETHERNET,
    lib_path: Optional[str] = None,
) -> Tuple[bool, Dict[str, str]]:
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
    If not specified marine path is set to /user/lib64/libmarine.so .
    """
    return init_instance(lib_path).filter_and_parse(
        packet=packet,
        bpf=bpf,
        display_filter=display_filter,
        fields=fields,
        macros=macros,
        encapsulation_type=encapsulation_type,
    )


def validate_bpf(
    bpf: str,
    encapsulation_type: int = encap_consts.ENCAP_ETHERNET,
    lib_path: Optional[str] = None,
) -> bool:
    """
    Validates the given BPF.
    By default the BPF is parsed with ethernet encapsulation,
    to view other possible encapsulation values view encap_consts.
    If not specified marine path is set to /user/lib64/libmarine.so .
    """
    return init_instance(lib_path).validate_bpf(
        bpf=bpf, encapsulation_type=encapsulation_type
    )


def validate_display_filter(
    display_filter: str, lib_path: Optional[str] = None,
) -> bool:
    """
    Validates the given display filter.
    If not specified marine path is set to /user/lib64/libmarine.so .
    """
    return init_instance(lib_path).validate_display_filter(
        display_filter=display_filter
    )


def validate_fields(
    fields: List[str],
    macros: Optional[Dict[str, List[str]]] = None,
    lib_path: Optional[str] = None,
) -> bool:
    """
    Validates the given fields. Fields have the same name as specified for Wireshark.
    If you want to add a custom field, you need to have the required dissector in your Wireshark plugins folder.
    Macros can be used to expand a field - Example macro format: {"macro.ip.src" : ["ip.src", "ipv6.src"]}.
    If not specified marine path is set to /user/lib64/libmarine.so .
    """
    return init_instance(lib_path).validate_fields(fields=fields, macros=macros)


def get_marine(
    lib_path: Optional[str] = None
) -> Marine:
    """
    Gets the marine object at a certian path.
    If not specified marine path is set to /user/lib64/libmarine.so .
    """
    return init_instance(lib_path)
