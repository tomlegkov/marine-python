#!/bin/bash

# This is a patch to handle auditwheel's bug with recursive depenencides:
# https://github.com/pypa/auditwheel/issues/48

sed -i 's/if is_py_ext:/if True:/g' /auditwheel/wheel_abi.py
