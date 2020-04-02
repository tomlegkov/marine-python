import itertools
import math
import multiprocessing
from dataclasses import dataclass
from functools import partial
from typing import List, Dict, Optional, Tuple

from marine import Marine


@dataclass
class MarinePool:
    _lib_path: str
    process_count: int = 4

    def filter_and_parse(
        self,
        packets: List[bytes],
        bpf: Optional[str] = None,
        display_filter: Optional[str] = None,
        fields: Optional[List[str]] = None,
    ) -> List[Tuple[bool, Dict[str, str]]]:
        if len(packets) == 0:
            return []

        ctx = multiprocessing.get_context("spawn")
        pool = ctx.Pool(self.process_count)
        chunk_size = int(math.ceil(len(packets) / float(self.process_count)))
        packet_chunks = [
            packets[i : i + chunk_size] for i in range(0, len(packets), chunk_size)
        ]
        filter_func = partial(
            self._filter_and_parse,
            bpf=bpf,
            display_filter=display_filter,
            fields=fields,
        )

        try:
            return list(itertools.chain(*pool.map(filter_func, packet_chunks)))
        finally:
            pool.close()

    def _filter_and_parse(
        self,
        packets: List[bytes],
        bpf: Optional[str] = None,
        display_filter: Optional[str] = None,
        fields: Optional[List[str]] = None,
    ) -> List[Tuple[bool, Dict[str, str]]]:
        m = Marine(self._lib_path)
        return [m.filter_and_parse(p, bpf, display_filter, fields) for p in packets]
