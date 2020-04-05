import math
import multiprocessing
from itertools import repeat
from typing import List, Dict, Optional, Tuple

from marine import Marine


class MarinePool:
    _marine_instance = None

    def __init__(self, lib_path: str, process_count: int = 4):
        self._lib_path = lib_path
        self.process_count = process_count

    def __enter__(self):
        ctx = multiprocessing.get_context("spawn")
        # Using spawn so child processes won't get the already initialized marine from the parent process.
        self.pool = ctx.Pool(self.process_count)
        self.pool.map(MarinePool._init_marine, repeat(self._lib_path, self.process_count))
        return self

    def filter_and_parse(
            self,
            packets: List[bytes],
            bpf: Optional[str] = None,
            display_filter: Optional[str] = None,
            fields: Optional[List[str]] = None,
    ) -> List[Tuple[bool, Dict[str, str]]]:
        if len(packets) == 0:
            return []

        chunk_size = int(math.ceil(len(packets) / float(self.process_count)))
        return self.pool.starmap(
            MarinePool._filter_and_parse,
            zip(packets, repeat(bpf), repeat(display_filter), repeat(fields)),
            chunksize=chunk_size,
        )

    @staticmethod
    def _init_marine(lib_path):
        MarinePool._marine_instance = Marine(lib_path)

    @staticmethod
    def _filter_and_parse(*args):
        return MarinePool._marine_instance.filter_and_parse(*args)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.pool.close()
