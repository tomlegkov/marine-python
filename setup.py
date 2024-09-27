from setuptools import setup

setup(
    name="marine",
    version="3.1.2",
    description="Python client for Marine",
    packages=["marine"],
    include_package_data=True,
    package_data={
        "marine": [".ws/libs/*.so*", ".ws/data/*"],
    },
)
