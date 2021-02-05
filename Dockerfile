ARG MARINE_CORE_TAG=marine

FROM domerd/marine-core:$MARINE_CORE_TAG as builder

WORKDIR /marine-python

COPY setup.py setup.cfg ./
COPY README.md ./
COPY LICENSE ./
COPY marine ./marine

ENV PY="/opt/python/cp38-cp38/bin/python"

RUN mkdir marine/.wslibs && \
    cp /build/run/libmarine.so /build/run/lib*so.0 marine/.wslibs/ && \
    $PY setup.py bdist_wheel --dist-dir /tmp

WORKDIR /dist

COPY scripts /scripts

RUN /scripts/expose_auditwheel.sh && \
    $PY /scripts/modify_auditwheel_policy.py && \
    /scripts/patch_auditwheel_recursive_dependency_bug.sh

RUN auditwheel repair -w /dist /tmp/marine*.whl



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
