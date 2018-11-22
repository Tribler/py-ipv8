from __future__ import absolute_import

from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pyipv8',
    author='Tribler',
    description='The Python implementation of the IPV8 library',
    long_description=long_description,
    long_description_content_type='text/markdown',
    version='1.3',
    url='https://github.com/Tribler/py-ipv8',
    package_data={'': ['*.*']},
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "libnacl",
        "netifaces",
        "Twisted",
        "pyOpenSSL",
        "six"
    ]
)
