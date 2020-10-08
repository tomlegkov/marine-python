FROM marine-core

RUN python3.8 -m pip install tox

WORKDIR /marine-python

CMD tox
