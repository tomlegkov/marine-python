#!/bin/bash

LD_LIBRARY_PATH=/projects/marine-core/cmake-build-debug/run python3.8 -m benchmark.main "$@"