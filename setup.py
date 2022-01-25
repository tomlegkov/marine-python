from setuptools import setup

setup(
    name="marine",
    version="3.1.1",
    description="Python client for Marine",
    url="https://github.com/tomlegkov/marine-python",
    author="Tom Legkov",
    author_email="tom.legkov@outlook.com",
    packages=["marine"],
    include_package_data=True,
    package_data={
        "marine": [".ws/libs/*.so*", ".ws/data/*"],
    },
)
