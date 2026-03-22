from setuptools import setup

from marine._version import __version__

setup(
    name="marine",
    version=__version__,
    description="Python client for Marine",
    packages=["marine"],
    include_package_data=True,
    package_data={
        "marine": [".ws/libs/*.so*", ".ws/data/*"],
    },
)
