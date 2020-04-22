import math
import multiprocessing
from itertools import repeat
from typing import List, Dict, Optional, Tuple, ClassVar

from marine import Marine


class MarinePool:
    _marine_instance: ClassVar[Optional[Marine]] = None

    def __init__(
        self,
        lib_path: str,
        epan_auto_reset_count: int,
        process_count: int = 4,
        preferences: Optional[List[str]] = None,
    ):
        self.pool = None
        self._lib_path = lib_path
        self._epan_auto_reset_count = epan_auto_reset_count
        self._process_count = process_count
        self.preferences = preferences

    def __enter__(self):
        self._create_pool()
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

        chunk_size = int(math.ceil(len(packets) / float(self._process_count)))
        return self.pool.starmap(
            self._filter_and_parse,
            zip(packets, repeat(bpf), repeat(display_filter), repeat(fields)),
            chunksize=chunk_size,
        )

    def set_preferences(self, preferences: List[str]) -> int:
        # Because each process have a marine instance, and there is no way to tell each process to run
        # the _marine_instance.set_preferences, we need to recreate the pool with the new configuration
        self.preferences = preferences
        self.pool.close()
        self.pool.join()
        self._create_pool()

    def _create_pool(self):
        ctx = multiprocessing.get_context("spawn")
        # Using spawn so child processes won't get the already initialized marine from the parent process.
        # We do that because initializing marine more than one time in a process causes SIGTRAP
        self.pool = ctx.Pool(
            self._process_count,
            initializer=self._init_marine,
            initargs=[self._lib_path, self._epan_auto_reset_count, self.preferences],
        )

    @classmethod
    def _init_marine(
        cls, lib_path: str, epan_auto_reset_count: int, preferences: List[str] = None
    ) -> None:
        cls._marine_instance = Marine(lib_path, epan_auto_reset_count, preferences)

    @classmethod
    def _filter_and_parse(
        cls,
        packet: bytes,
        bpf: Optional[str] = None,
        display_filter: Optional[str] = None,
        fields: Optional[list] = None,
    ) -> (bool, Dict[str, str]):
        return cls._marine_instance.filter_and_parse(
            packet, bpf, display_filter, fields
        )

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.pool.close()
