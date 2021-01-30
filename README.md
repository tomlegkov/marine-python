# Marine Python Client
Python client for [Marine](https://github.com/tomlegkov/marine-core)

## Installation
```shell script
pip install marine
```

## Usage
```python
import marine

passed, result = marine.filter_and_parse_packet(b"your packet", "ip host 1.1.1.1", "tcp.port == 80", ["ip.src", "ip.dst"])
if passed:
    print(f"{result['ip.src']} -> {result['ip.dst']}")

# Also available
marine.parse_packet(...)
marine.filter_packet(...)
marine.validate_fields(...)
marine.validate_display_filter(...)
marine.validate_bpf(...)
```
For advanced usages (not recommended) see the `get_marine()` function and the `Marine` class    

## Contributing
### Guidelines
Syntax formatting is done using [Black](https://github.com/psf/black)

### Running Tests
The tests are written using pytest. To run the tests, you need to provide the library file (`libmarine.so`) and its dependencies.
`marine` expects `libmarine.so` to reside in `marine/.wslibs`.

Then, simply run `tox`.

Additionally, syntax is checked with flake8 by running `flake8 marine tests` from the root directory of the project.

### Packaging
An `x86_64` `manylinux2014` wheel is built by our CI, based on a `manylinux` image supplied by `marine-core` and patched to meet our needs.
There is currently no support for installing on other platfroms

-------

Tom Legkov <tom.legkov@outlook.com>
