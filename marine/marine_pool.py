import math
import multiprocessing
from itertools import repeat
from typing import List, Dict, Optional, Tuple, ClassVar

from .marine import Marine


class MarinePool:
    _marine_instance: ClassVar[Optional[Marine]] = None

    def __init__(
        self, epan_auto_reset_count: Optional[int] = None, process_count: int = 4
    ):
        self._epan_auto_reset_count = epan_auto_reset_count
        self._process_count = process_count

        ctx = multiprocessing.get_context("spawn")
        # Using spawn so child processes won't get the already initialized marine from the parent process.
        # We do that because initializing marine more than one time in a process causes SIGTRAP
        self.pool = ctx.Pool(
            self._process_count,
            initializer=self._init_marine,
            initargs=[self._epan_auto_reset_count],
        )

    def __enter__(self):
        return self

    def filter(
        self,
        packets: List[bytes],
        bpf: Optional[str] = None,
        display_filter: Optional[str] = None,
        encapsulation_type: Optional[int] = None,
    ) -> List[bool]:
        result = self.filter_and_parse(
            packets=packets,
            bpf=bpf,
            display_filter=display_filter,
            encapsulation_type=encapsulation_type,
        )

        return [passed for passed, _ in result]

    def parse(
        self,
        packets: List[bytes],
        fields: Optional[List[str]] = None,
        encapsulation_type: Optional[int] = None,
        field_templates: Optional[Dict[str, List[str]]] = None,
    ) -> List[Dict[str, Optional[str]]]:
        result = self.filter_and_parse(
            packets=packets,
            fields=fields,
            encapsulation_type=encapsulation_type,
            field_templates=field_templates,
        )

        return [values for _, values in result]

    def filter_and_parse(
        self,
        packets: List[bytes],
        bpf: Optional[str] = None,
        display_filter: Optional[str] = None,
        fields: Optional[List[str]] = None,
        encapsulation_type: Optional[int] = None,
        field_templates: Optional[Dict[str, List[str]]] = None,
    ) -> List[Tuple[bool, Dict[str, Optional[str]]]]:
        if len(packets) == 0:
            return []

        chunk_size = int(math.ceil(len(packets) / float(self._process_count)))
        return self.pool.starmap(
            self._filter_and_parse,
            zip(
                packets,
                repeat(bpf),
                repeat(display_filter),
                repeat(fields),
                repeat(encapsulation_type),
                repeat(field_templates),
            ),
            chunksize=chunk_size,
        )

    @classmethod
    def _init_marine(cls, epan_auto_reset_count: int) -> None:
        cls._marine_instance = Marine(epan_auto_reset_count)

    @classmethod
    def _filter_and_parse(
        cls,
        packet: bytes,
        bpf: Optional[str] = None,
        display_filter: Optional[str] = None,
        fields: Optional[list] = None,
        encapsulation_type: Optional[int] = None,
        field_templates: Optional[Dict[str, List[str]]] = None,
    ) -> (bool, Dict[str, str]):
        return cls._marine_instance.filter_and_parse(
            packet, bpf, display_filter, fields, encapsulation_type, field_templates
        )

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.pool.close()

    def close(self):
        self.pool.close()
