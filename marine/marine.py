from ctypes import *
from typing import Optional, List, Dict, Tuple, NamedTuple

from .exceptions import (
    BadBPFException,
    BadDisplayFilterException,
    InvalidFieldException,
    UnknownInternalException,
)
from . import encap_consts


class MarineResult(Structure):
    _fields_ = [("output", POINTER(c_char_p)), ("len", c_uint), ("result", c_int)]


MARINE_RESULT_POINTER = POINTER(MarineResult)
MARINE_NAME = "libmarine.so"


class MarineFieldsValidationResult(NamedTuple):
    valid: bool
    errors: List[str]

    def __bool__(self) -> bool:
        return self.valid


class MarineFilterValidationResult(NamedTuple):
    valid: bool
    error: Optional[str]

    def __bool__(self) -> bool:
        return self.valid


class Marine:
    SUGGESTED_FIELD_TEMPLATES = {
        "macro.ip.src": ["ip.src", "arp.src.proto_ipv4"],
        "macro.ip.dst": ["ip.dst", "arp.dst.proto_ipv4"],
        "macro.src_port": ["tcp.srcport", "udp.srcport"],
        "macro.dst_port": ["tcp.dstport", "udp.dstport"],
    }
    WIFI_RADIO_PROTOCOLS = frozenset(["radiotap", "wlan", "wlan_radio"])

    def __init__(self, epan_auto_reset_count: Optional[int] = None):
        try:
            cdll.LoadLibrary(MARINE_NAME)
        except Exception:
            raise OSError(
                "Could not load Marine. Please make sure you have put marine in LD_LIBRARY_PATH."
            )

        self._filters_cache = dict()
        self._field_templates_cache = dict()
        self._encap_cache = dict()
        self._marine = CDLL(MARINE_NAME)
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
        encapsulation_type: Optional[int] = None,
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
        encapsulation_type: Optional[int] = None,
        field_templates: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Optional[str]]:
        _, result = self.filter_and_parse(
            packet=packet,
            fields=fields,
            encapsulation_type=encapsulation_type,
            field_templates=field_templates,
        )

        return result

    def filter_and_parse(
        self,
        packet: bytes,
        bpf: Optional[str] = None,
        display_filter: Optional[str] = None,
        fields: Optional[List[str]] = None,
        encapsulation_type: Optional[int] = None,
        field_templates: Optional[Dict[str, List[str]]] = None,
    ) -> (bool, Dict[str, Optional[str]]):
        if bpf is None and display_filter is None and fields is None:
            raise ValueError(
                "At least one form of dissection must be passed to the function"
            )

        if isinstance(bpf, str):
            bpf = bpf.encode("utf-8")
        if isinstance(display_filter, str):
            display_filter = display_filter.encode("utf-8")

        if fields is not None:
            expanded_fields, field_template_indices = self._expand_field_templates(
                fields, field_templates
            )
            encoded_fields = [
                f.encode("utf-8") if isinstance(f, str) else f for f in expanded_fields
            ]
        else:
            expanded_fields, field_template_indices = None, None
            encoded_fields = None

        if encapsulation_type is None:
            encapsulation_type = self._detect_encap(expanded_fields)

        filter_key = (
            bpf,
            display_filter,
            tuple(encoded_fields) if fields is not None else None,
            tuple(field_template_indices)
            if field_template_indices is not None
            else None,
            encapsulation_type,
        )
        if filter_key in self._filters_cache:
            filter_id = self._filters_cache[filter_key]
        else:
            filter_id = self._add_or_get_filter(
                bpf,
                display_filter,
                encoded_fields,
                field_template_indices,
                encapsulation_type,
            )
            self._filters_cache[filter_key] = filter_id

        marine_result = self._marine.marine_dissect_packet(
            filter_id, packet, len(packet)
        )
        success, result = False, None
        if marine_result.contents.result == 1:
            success = True
            if fields is not None:
                parsed_output = self._parse_output(
                    marine_result.contents.output, marine_result.contents.len
                )
                result = dict(zip(fields, parsed_output))

        self._marine.marine_free(marine_result)
        return success, result

    def _resolve_err_msg(self, err_msg: POINTER(POINTER(c_char))) -> Optional[str]:
        if not err_msg.contents:
            return None
        error = string_at(err_msg.contents)
        self._marine.marine_free_err_msg(err_msg.contents)
        return error.decode("utf-8")

    def validate_bpf(
        self, bpf: str, encapsulation_type: int = encap_consts.ENCAP_ETHERNET
    ) -> MarineFilterValidationResult:
        bpf = bpf.encode("utf-8")
        err_msg = pointer(POINTER(c_char)())
        valid = bool(self._marine.validate_bpf(bpf, encapsulation_type, err_msg))
        error = self._resolve_err_msg(err_msg)
        return MarineFilterValidationResult(valid, error)

    def validate_display_filter(
        self, display_filter: str
    ) -> MarineFilterValidationResult:
        display_filter = display_filter.encode("utf-8")
        err_msg = pointer(POINTER(c_char)())
        valid = bool(self._marine.validate_display_filter(display_filter, err_msg))
        error = self._resolve_err_msg(err_msg)
        return MarineFilterValidationResult(valid, error)

    def validate_fields(
        self, fields: List[str], field_templates: Optional[Dict[str, List[str]]] = None
    ) -> MarineFieldsValidationResult:
        fields, _ = self._expand_field_templates(fields, field_templates)
        fields_len = len(fields)
        fields = [field.encode("utf-8") for field in fields]
        fields_c_arr = (c_char_p * fields_len)(*fields)
        err_msg = pointer(POINTER(c_char)())
        valid = bool(self._marine.validate_fields(fields_c_arr, fields_len, err_msg))
        error = self._resolve_err_msg(err_msg)
        return MarineFieldsValidationResult(
            valid, [] if error is None else error.split("\t")
        )

    @staticmethod
    def _parse_output(output: POINTER(c_char_p), length: int) -> List[Optional[str]]:
        return list(
            output[i][:].decode("utf-8") if output[i] is not None else None
            for i in range(length)
        )

    def _add_or_get_filter(
        self,
        bpf: Optional[bytes] = None,
        display_filter: Optional[bytes] = None,
        fields: Optional[List[bytes]] = None,
        field_template_indices: Optional[List[int]] = None,
        encapsulation_type: int = encap_consts.ENCAP_ETHERNET,
    ) -> int:
        if fields is not None:
            fields_len = len(fields)
            fields_c_arr = (c_char_p * fields_len)(*fields)
        else:
            fields_len = 0
            fields_c_arr = None

        field_template_indices_c_arr = (
            (c_int * fields_len)(*field_template_indices)
            if field_template_indices is not None
            else None
        )
        err_msg = pointer(POINTER(c_char)())
        filter_id = self._marine.marine_add_filter(
            bpf,
            display_filter,
            fields_c_arr,
            field_template_indices_c_arr,
            fields_len,
            encapsulation_type,
            err_msg,
        )
        error = self._resolve_err_msg(err_msg)
        if filter_id < 0:
            if filter_id == c_int.in_dll(self._marine, "BAD_BPF_ERROR_CODE").value:
                raise BadBPFException(error)
            elif (
                filter_id
                == c_int.in_dll(self._marine, "BAD_DISPLAY_FILTER_ERROR_CODE").value
            ):
                raise BadDisplayFilterException(error)
            elif (
                filter_id
                == c_int.in_dll(self._marine, "INVALID_FIELD_ERROR_CODE").value
            ):
                raise InvalidFieldException(error)
            raise UnknownInternalException(error)
        return filter_id

    def __del__(self):
        if getattr(self, "_marine", None):
            self._marine.destroy_marine()

    def _expand_field_templates(
        self, fields: List[str], field_templates: Optional[Dict[str, List[str]]]
    ) -> Tuple[Tuple[str, ...], Optional[Tuple[int, ...]]]:
        if not field_templates:
            return tuple(fields), None

        field_template_key = (
            tuple(fields),
            frozenset((key, tuple(value)) for key, value in field_templates.items()),
        )
        if field_template_key in self._field_templates_cache:
            return self._field_templates_cache[field_template_key]
        else:
            expanded_with_indices = [
                (possible_field, field_template_id)
                for field_template_id, field in enumerate(fields)
                for possible_field in field_templates.get(field, [field])
            ]
            ret_value = tuple(zip(*expanded_with_indices))
            self._field_templates_cache[field_template_key] = ret_value
            return ret_value

    def _detect_encap(self, fields: Optional[List[str]]) -> int:
        if not fields:
            return encap_consts.ENCAP_ETHERNET

        encap_key = frozenset(fields)
        if encap_key in self._encap_cache:
            return self._encap_cache[encap_key]

        fields_protocols = frozenset(field.split(".")[0].lower() for field in fields)
        if fields_protocols.intersection(self.WIFI_RADIO_PROTOCOLS):
            self._encap_cache[encap_key] = encap_consts.ENCAP_IEEE_802_11_RADIOTAP
            return encap_consts.ENCAP_IEEE_802_11_RADIOTAP

        self._encap_cache[encap_key] = encap_consts.ENCAP_ETHERNET
        return encap_consts.ENCAP_ETHERNET
