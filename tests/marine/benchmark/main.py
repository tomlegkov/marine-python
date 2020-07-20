""""
Marine Python Benchmark

The benchmark is written to achieve 2 goals:
1) Understand how fast Marine performs (specifically in the Python client) and find bottlenecks
2) See that memory usage doesn't increase

The following things are benchmarked:
1) Filter only with BPF
2) Filter only with display filter
3) Filter with BPF + display filter
4) Extract 3 fields
5) Extract 8 fields
6) Filter with BPF + display filter + extract 3 fields
7) Filter with BPF + display filter + extract 8 fields

By default, all of the benchmarks are executed.

For accurate memory testing, the packet count should be passed as a multiple of AUTO_RESET_COUNT.
TODO: allow passing packet count as a parameter
TODO: allow setting AUTO_RESET_COUNT as a parameter (blocked on issue #4 in marine-core)

The generated packets will contain multiple protocols, and will purposely contain many different conversations,
in order for the benchmarks to fill up the conversation table "naturally" and see how it affects performance.
TODO: add HTTP, DNS, ARP.
TODO: simulate PL in conversations
TODO: add support for real TCP conversations with ack and seq management
"""
import argparse
import os
import time
from typing import List, Callable, Dict

import psutil

from marine import Marine, encap_consts
from .benchmark_generator import generate_packets
from .utils import BenchmarkPacket

AUTO_RESET_COUNT = (
    20000  # TODO use marine_instance.get_epan_reset_count() when it's implemented
)

marine_instance = Marine(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "..",
        "fixtures",
        "marine",
        "libmarine.so",
    )
)
process = psutil.Process()
benchmark_functions: Dict[str, Callable[[List[BenchmarkPacket]], None]] = dict()


def get_used_memory_in_mb() -> float:
    return process.memory_info().rss / 1024.0 / 1024.0


def create_3_expected_fields(packet: BenchmarkPacket) -> Dict[str, str]:
    return {
        field: packet.expected_parse_result[field]
        for field in packet.fields_to_extract[:3]
    }


def benchmark_wrapper(f: Callable[[List[BenchmarkPacket]], None]):
    def benchmark_timer(packets: List[BenchmarkPacket]):
        start_used_memory = get_used_memory_in_mb()
        start_time = time.time()
        f(packets)
        end_time = time.time()
        end_used_memory = get_used_memory_in_mb()
        delta_time = end_time - start_time
        delta_used_memory = end_used_memory - start_used_memory
        print(
            f"""
Executed {f.__name__} on {len(packets)} packets in {delta_time:.2f} seconds,
which is {(len(packets) / delta_time):.2f} packets per second.
Started with {start_used_memory:.2f} MB, ended with {end_used_memory:.2f}. Delta is {delta_used_memory:.2f} MB.
"""
        )

    benchmark_functions[f.__name__] = benchmark_timer
    return benchmark_timer


@benchmark_wrapper
def benchmark_bpf(packets: List[BenchmarkPacket]):
    for packet in packets:
        passed, result = marine_instance.filter_and_parse(
            packet.packet,
            bpf=packet.good_bpf,
            encapsulation_type=encap_consts.ENCAP_ETHERNET,
        )
        assert passed
        assert result is None


@benchmark_wrapper
def benchmark_display_filter(packets: List[BenchmarkPacket]):
    for packet in packets:
        passed, result = marine_instance.filter_and_parse(
            packet.packet,
            display_filter=packet.good_display_filter,
            encapsulation_type=encap_consts.ENCAP_ETHERNET,
        )
        assert passed
        assert result is None


@benchmark_wrapper
def benchmark_bpf_and_display_filter(packets: List[BenchmarkPacket]):
    for packet in packets:
        passed, result = marine_instance.filter_and_parse(
            packet.packet,
            bpf=packet.good_bpf,
            display_filter=packet.good_display_filter,
            encapsulation_type=encap_consts.ENCAP_ETHERNET,
        )
        assert passed
        assert result is None


@benchmark_wrapper
def benchmark_3_fields(packets: List[BenchmarkPacket]):
    for packet in packets:
        passed, result = marine_instance.filter_and_parse(
            packet.packet,
            fields=packet.fields_to_extract[:3],
            encapsulation_type=encap_consts.ENCAP_ETHERNET,
        )
        assert passed
        assert create_3_expected_fields(packet) == result


@benchmark_wrapper
def benchmark_8_fields(packets: List[BenchmarkPacket]):
    for packet in packets:
        passed, result = marine_instance.filter_and_parse(
            packet.packet,
            fields=packet.fields_to_extract,
            encapsulation_type=encap_consts.ENCAP_ETHERNET,
        )
        assert passed
        assert packet.expected_parse_result == result


@benchmark_wrapper
def benchmark_bpf_and_display_filter_and_3_fields(packets: List[BenchmarkPacket]):
    for packet in packets:
        passed, result = marine_instance.filter_and_parse(
            packet.packet,
            bpf=packet.good_bpf,
            display_filter=packet.good_display_filter,
            fields=packet.fields_to_extract[:3],
            encapsulation_type=encap_consts.ENCAP_ETHERNET,
        )
        assert passed
        assert create_3_expected_fields(packet) == result


@benchmark_wrapper
def benchmark_bpf_and_display_filter_and_8_fields(packets: List[BenchmarkPacket]):
    for packet in packets:
        passed, result = marine_instance.filter_and_parse(
            packet.packet,
            bpf=packet.good_bpf,
            display_filter=packet.good_display_filter,
            fields=packet.fields_to_extract,
            encapsulation_type=encap_consts.ENCAP_ETHERNET,
        )
        assert passed
        assert packet.expected_parse_result == result


@benchmark_wrapper
def benchmark_bpf_and_display_filter_and_8_fields_auto_detection(
    packets: List[BenchmarkPacket],
):
    for packet in packets:
        passed, result = marine_instance.filter_and_parse(
            packet.packet,
            bpf=packet.good_bpf,
            display_filter=packet.good_display_filter,
            fields=packet.fields_to_extract,
        )
        assert passed
        assert packet.expected_parse_result == result


@benchmark_wrapper
def benchmark_bpf_and_display_filter_and_8_fields_with_macros(
    packets: List[BenchmarkPacket],
):
    for packet in packets:
        passed, result = marine_instance.filter_and_parse(
            packet.packet,
            bpf=packet.good_bpf,
            display_filter=packet.good_display_filter,
            fields=packet.fields_to_extract,
            macros=Marine.SUGGESTED_MACROS,
            encapsulation_type=encap_consts.ENCAP_ETHERNET,
        )
        assert passed
        assert packet.expected_parse_result == result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--benchmark", choices=["all"] + list(benchmark_functions.keys())
    )
    args = parser.parse_args()
    run_all_functions = not args.benchmark or args.benchmark == "all"
    packet_multiplier = len(benchmark_functions) if run_all_functions else 1
    print("Generating packets...")
    generated_packets = generate_packets(AUTO_RESET_COUNT * packet_multiplier)
    print("Done generating, executing benchmarks...")
    benchmark_start_used_memory = get_used_memory_in_mb()

    if run_all_functions:
        for i, benchmark_function in enumerate(benchmark_functions.values()):
            benchmark_function(
                generated_packets[i * AUTO_RESET_COUNT : (i + 1) * AUTO_RESET_COUNT]
            )
    elif args.benchmark in benchmark_functions:
        benchmark_functions[args.benchmark](generated_packets)
    else:
        raise ValueError("Pick a benchmark")

    benchmark_end_used_memory = get_used_memory_in_mb()
    memory_delta = benchmark_end_used_memory - benchmark_start_used_memory
    print(
        f"Total memory usage (over all of the benchmarks) increased by {memory_delta:.2f} MB"
    )
