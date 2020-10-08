FROM marine-core:marine

RUN python3.8 -m pip install tox

WORKDIR /marine-python

CMD tox
