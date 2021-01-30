#!/bin/bash -e
to="$1"
python_exe=$(head -n1 $(which auditwheel) | cut -d'!' -f2-)
site_packages=$($python_exe -c 'import site; print(site.getsitepackages()[0])')
ln -s "$site_packages/auditwheel" "$to/auditwheel"
