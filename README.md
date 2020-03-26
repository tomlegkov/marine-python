# Marine Python Client
Python client for [Marine](https://github.com/tomlegkov/marine-core)

## Installation
```shell script
pip install marine
```

## Usage
1. 
    Initialize an instance of Marine (note that only one can be initialized per process):
    ```python
    marine_instance = Marine('path to libmarine.so')
    ```
   
2.
    Call the method `filter_and_parse` with a BPF, a display filter and fields to parse.
    Every parameter is optional - if it's passed as `None` then it won't be applied to the packet, but at least one parameter is required. 
    ```python
    passed, output = marine_instance.filter_and_parse(b'your packet', 'ip', 'tcp', ['ip.src', 'ip.dst'])
   ```
   
3. 
    `passed` is a boolean inidicating whether or not the packet passed the filter. 
    If a filter wasn't supplied, it will be `True`.

    `output` is a dict between field name to its parsed value.
     If the packet didn't pass the filter or fields weren't passed to the function, it will be `None`.
    

## Contributing
### Guidelines
Syntax formatting is done using [Black](https://github.com/psf/black)

### Running Tests
The tests are written using pytest. To run the tests, you need to provide the library file (`libmarine.so`),
and place it next to the file `tests/fixtures/marine/marine_fixtures.py`.

Then, simply run `tox`.

Additionally, syntax is checked with flake8 by running `flake8 marine tests` from the root directory of the project.

-------

Tom Legkov <tom.legkov@outlook.com>