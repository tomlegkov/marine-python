import csv
import os
import sys
from ctypes import *
from io import StringIO
from typing import Optional, List, Dict, Tuple

from .exceptions import (
    BadBPFException,
    BadDisplayFilterException,
    InvalidFieldException,
    UnknownInternalException,
)
from . import encap_consts


class MarineResult(Structure):
    _fields_ = [("output", c_char_p), ("result", c_int)]


MARINE_RESULT_POINTER = POINTER(MarineResult)


class Marine:
    SUGGESTED_MACROS = {
        "macro.ip.src": ["ip.src", "arp.src.proto_ipv4"],
        "macro.ip.dst": ["ip.dst", "arp.dst.proto_ipv4"],
        "macro.src_port": ["tcp.srcport", "udp.srcport"],
        "macro.dst_port": ["tcp.dstport", "udp.dstport"],
    }

    def __init__(self, lib_path: Optional[str] = None, epan_auto_reset_count: Optional[int] = None):
        if lib_path is None:
            lib_path = os.path.join(sys.prefix, "lib64", "libmarine.so")

        if not os.path.exists(lib_path):
            raise ValueError(f"Marine could not be located at {lib_path}")

        try:
            cdll.LoadLibrary(lib_path)
        except Exception:
            raise OSError("Could not load Marine")

        self._filters_cache = dict()
        self._macros_cache = dict()
        self._marine = CDLL(lib_path)
        self._marine.marine_dissect_packet.restype = MARINE_RESULT_POINTER
        self._marine.marine_free.argtypes = [MARINE_RESULT_POINTER]
        return_code = self._marine.init_marine()
        if return_code < 0:
            if (
                return_code
                == c_int.in_dll(
                    self._marine, "MARINE_ALREADY_INITIALIZED_ERROR_CODE"
                ).value
            ):
                raise RuntimeError("Marine is already initialized")
            raise RuntimeError("Could not initialize Marine")

        if epan_auto_reset_count:
            self._marine.set_epan_auto_reset_count(epan_auto_reset_count)

    @property
    def epan_auto_reset_count(self) -> int:
        return self._marine.get_epan_auto_reset_count()

    @epan_auto_reset_count.setter
    def epan_auto_reset_count(self, value: int) -> None:
        self._marine.set_epan_auto_reset_count(value)

    def filter(
        self,
        packet: bytes,
        bpf: Optional[str] = None,
        display_filter: Optional[str] = None,
        encapsulation_type: int = encap_consts.ENCAP_ETHERNET,
    ) -> bool:
        passed, _ = self.filter_and_parse(
            packet=packet,
            bpf=bpf,
            display_filter=display_filter,
            encapsulation_type=encapsulation_type,
        )

        return passed

    def parse(
        self,
        packet: bytes,
        fields: Optional[List[str]] = None,
        encapsulation_type: int = encap_consts.ENCAP_ETHERNET,
        macros: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, str]:
        _, result = self.filter_and_parse(
            packet=packet,
            fields=fields,
            encapsulation_type=encapsulation_type,
            macros=macros,
        )

        return result

    def filter_and_parse(
        self,
        packet: bytes,
        bpf: Optional[str] = None,
        display_filter: Optional[str] = None,
        fields: Optional[List[str]] = None,
        encapsulation_type: int = encap_consts.ENCAP_ETHERNET,
        macros: Optional[Dict[str, List[str]]] = None,
    ) -> (bool, Dict[str, str]):
        if bpf is None and display_filter is None and fields is None:
            raise ValueError(
                "At least one form of dissection must be passed to the function"
            )

        if isinstance(bpf, str):
            bpf = bpf.encode("utf-8")
        if isinstance(display_filter, str):
            display_filter = display_filter.encode("utf-8")

        if fields is not None:
            expanded_fields, macro_indices = self._expand_macros(fields, macros)
            encoded_fields = [
                f.encode("utf-8") if isinstance(f, str) else f for f in expanded_fields
            ]
        else:
            expanded_fields, macro_indices = None, None
            encoded_fields = None

        filter_key = (
            bpf,
            display_filter,
            tuple(encoded_fields) if fields is not None else None,
            tuple(macro_indices) if macro_indices is not None else None,
            encapsulation_type,
        )
        if filter_key in self._filters_cache:
            filter_id = self._filters_cache[filter_key]
        else:
            filter_id, err = self._add_or_get_filter(
                bpf, display_filter, encoded_fields, macro_indices, encapsulation_type
            )
            if filter_id < 0:
                if filter_id == c_int.in_dll(self._marine, "BAD_BPF_ERROR_CODE").value:
                    raise BadBPFException(err)
                elif (
                    filter_id
                    == c_int.in_dll(self._marine, "BAD_DISPLAY_FILTER_ERROR_CODE").value
                ):
                    raise BadDisplayFilterException(err)
                elif (
                    filter_id
                    == c_int.in_dll(self._marine, "INVALID_FIELD_ERROR_CODE").value
                ):
                    raise InvalidFieldException(err)
                raise UnknownInternalException(err)
            self._filters_cache[filter_key] = filter_id

        packet_data = self._prepare_packet_data(packet)
        marine_result = self._marine.marine_dissect_packet(
            filter_id, packet_data, len(packet_data)
        )
        success, result = False, None
        if marine_result.contents.result == 1:
            success = True
            if fields is not None:
                parsed_output = self._parse_output(
                    marine_result.contents.output.decode("utf-8")
                )
                result = dict(zip(fields, parsed_output))

        self._marine.marine_free(marine_result)
        return success, result

    def validate_bpf(
        self, bpf: str, encapsulation_type: int = encap_consts.ENCAP_ETHERNET
    ) -> bool:
        bpf = bpf.encode("utf-8")
        return bool(self._marine.validate_bpf(bpf, encapsulation_type))

    def validate_display_filter(self, display_filter: str) -> bool:
        display_filter = display_filter.encode("utf-8")
        return bool(self._marine.validate_display_filter(display_filter))

    def validate_fields(
        self, fields: List[str], macros: Optional[Dict[str, List[str]]] = None
    ) -> bool:
        fields, _ = self._expand_macros(fields, macros)
        fields_len = len(fields)
        fields = [field.encode("utf-8") for field in fields]
        fields_c_arr = (c_char_p * fields_len)(*fields)
        return bool(self._marine.validate_fields(fields_c_arr, fields_len))

    @staticmethod
    def _parse_output(output: str) -> List[str]:
        # TODO: this is a bottleneck. Find a better way to provide output from the c code
        f = StringIO(output)
        csv_parsed_output = next(csv.reader(f, delimiter="\t", quotechar='"'))
        return csv_parsed_output

    @staticmethod
    def _prepare_packet_data(packet: bytes):
        return (c_ubyte * len(packet)).from_buffer_copy(packet)

    def _add_or_get_filter(
        self,
        bpf: Optional[bytes] = None,
        display_filter: Optional[bytes] = None,
        fields: Optional[List[bytes]] = None,
        macro_indices: Optional[List[int]] = None,
        encapsulation_type: int = encap_consts.ENCAP_ETHERNET,
    ) -> (int, bytes):
        if fields is not None:
            fields_len = len(fields)
            fields_c_arr = (c_char_p * fields_len)(*fields)
        else:
            fields_len = 0
            fields_c_arr = None

        macro_indices_c_arr = (
            (c_int * fields_len)(*macro_indices) if macro_indices is not None else None
        )
        err_msg = pointer(POINTER(c_char)())
        filter_id = self._marine.marine_add_filter(
            bpf,
            display_filter,
            fields_c_arr,
            macro_indices_c_arr,
            fields_len,
            encapsulation_type,
            err_msg,
        )
        if err_msg.contents:
            err_msg_value = string_at(err_msg.contents)
            self._marine.marine_free_err_msg(err_msg.contents)
        else:
            err_msg_value = None
        return filter_id, err_msg_value

    def __del__(self):
        if getattr(self, "_marine", None):
            self._marine.destroy_marine()

    def _expand_macros(
        self, fields: List[str], macros: Optional[Dict[str, List[str]]]
    ) -> Tuple[Tuple[str, ...], Optional[Tuple[int, ...]]]:
        if not macros:
            return tuple(fields), None

        macro_key = (
            tuple(fields),
            frozenset((key, tuple(value)) for key, value in macros.items()),
        )
        if macro_key in self._macros_cache:
            return self._macros_cache[macro_key]
        else:
            expanded_with_indices = [
                (possible_field, macro_id)
                for macro_id, field in enumerate(fields)
                for possible_field in macros.get(field, [field])
            ]
            ret_value = tuple(zip(*expanded_with_indices))
            self._macros_cache[macro_key] = ret_value
            return ret_value
