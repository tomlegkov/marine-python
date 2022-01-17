ARG MARINE_CORE_TAG=marine

FROM tomlegkov/marine-core:$MARINE_CORE_TAG as builder

WORKDIR /marine-python

COPY setup.py setup.cfg ./
COPY README.md ./
COPY LICENSE ./
COPY marine ./marine

ENV PY="/opt/python/cp38-cp38/bin/python"

RUN mkdir -p marine/.ws/data && \
    rsync -L --exclude idl2wrs --exclude 'lib*.so*' --exclude 'plugins*' --exclude 'marine_*' --exclude tshark --exclude '*.html' --exclude 'lib*.a' /build/run/* marine/.ws/data/ && \
    mkdir marine/.ws/libs && \
    rsync -L /build/run/libmarine.so /build/run/lib*so.0 marine/.ws/libs/ && \
    $PY setup.py bdist_wheel --dist-dir /tmp

WORKDIR /dist

COPY scripts /scripts

RUN /scripts/expose_auditwheel.sh && \
    $PY /scripts/modify_auditwheel_policy.py && \
    /scripts/patch_auditwheel_recursive_dependency_bug.sh

RUN auditwheel repair --plat manylinux2014_x86_64 -w /dist /tmp/marine*.whl



FROM centos/python-38-centos7

USER root

RUN yum install -y libpcap && \
    yum clean all && \
    rm -rf /var/yum/cache

RUN  pip install --no-cache-dir tox

COPY . /marine-python

WORKDIR /marine-python

COPY --from=builder /dist /dist

VOLUME /io

# --import-mode is a pytest option
# It makes pytest import marine from site-packages (wheel) and not from the repo
CMD tox --installpkg /dist/marine*.whl -- --import-mode append
