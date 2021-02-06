# Marine Python Client
Python client for [Marine](https://github.com/tomlegkov/marine-core)

## Installation
Clone the repo and run:
```shell
python setup.py install
```

## Usage
### Basic Usage (filter and parse packet)
```python
import marine

passed, result = marine.filter_and_parse_packet(b"your packet", "ip host 1.1.1.1", "tcp.port == 80", ["ip.src", "ip.dst"])
if passed:
    print(f"{result['ip.src']} -> {result['ip.dst']}")
```

### Other Available API
#### Filter packet
```python
passed = marine.filter_packet(b"your packet", "ip host 1.1.1.1", "tcp.port == 80")
if not passed:
    print("Packet didn't pass filter")
```

#### Parse packet
```python
result = marine.parse_packet(b"your packet", ["macro.ip.src", "tcp.port"], {"macro.ip.src": ["ip.src", "ipv6.src"]})
print(f"Parsed IP: {result['macro.ip.src']} and port: {result['tcp.port']}")
```

#### BPF validation
```python
validation_result = marine.validate_bpf("ip host 1.1.1.1")
if not validation_result:
    print(f"BPF validation error: {validation_result.error}")
```

#### Display filter validation
```python
validation_result = marine.validate_display_filter("tcp.port == 80")
if not validation_result:
    print(f"Display filter validation error: {validation_result.error}")
```

#### Fields validation
```python
validation_result = marine.validate_fields(["macro.ip.src", "tcp.port"], {"macro.ip.src": ["ip.src", "ipv6.src"]})
if not validation_result:
    print(f"The following fields don't exist: {validation_result.errors}")
```

#### Pool
`MarinePool` allows to run multiple instances of Marine using multiple cores. 
The exported API is identical to Marine's: `filter`, `parse`, `filter_and_parse`.

```python
pool = MarinePool(process_count=4)
parsed_packets = pool.filter_and_parse(packets, bpf="udp", fields=["macro.ip.src", "udp.port"], field_templates={"macro.ip.src": ["ip.src", "ipv6.src"]})
for passed, result in parsed_packets:
    if passed:
        print(f"Parsed IP: {result['macro.ip.src']} and UDP port: {result['udp.port']}")
```


#### Advanced
For advanced usages (not recommended) see the `get_marine()` function and the `Marine` class    .

## Contributing
### Guidelines
Syntax formatting is done using [Black](https://github.com/psf/black)

### Running Tests
The tests are written using pytest. To run the tests, you need to provide the library file (`libmarine.so`) and its dependencies.
`marine` expects `libmarine.so` to reside in `marine/.wslibs`. Inside a development environment, you can simply create a link from `marine/.wslibs` to where you compile `marine-core`.

Then, simply run `tox`.

Additionally, syntax is checked with flake8 by running `flake8 marine tests` from the root directory of the project.

### Packaging
An `x86_64` `manylinux2014` wheel is built by our CI, based on a `manylinux` image supplied by `marine-core` and patched to meet our needs.
There is currently no support for installing on other platforms.