#!/bin/bash -e

# This is a patch to handle auditwheel's bug with recursive depenencides:
# https://github.com/pypa/auditwheel/issues/48

patch -i "$(dirname ${BASH_SOURCE[0]})/wheel_abi.patch" /auditwheel/wheel_abi.py
