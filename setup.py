from setuptools import find_packages, setup

with open("README.md") as fh:
    long_description = fh.read()

setup(
    name='pyipv8',
    author='Tribler',
    description='The Python implementation of the IPV8 library',
    long_description=long_description,
    long_description_content_type='text/markdown',
    version='2.13.0',  # Do not change manually! Handled by github_increment_version.py
    url='https://github.com/Tribler/py-ipv8',
    package_data={'': ['*.*']},
    packages=find_packages(),
    py_modules=['ipv8_service'],
    install_requires=[
        "cryptography",
        "libnacl",
        "aiohttp",
        "aiohttp_apispec",
        "pyOpenSSL",
        "pyasn1",
        "marshmallow",
        "typing-extensions",
        "packaging"
    ],
    extras_require={
        "all": ["asynctest; python_version=='3.7'", "coverage"],
        "tests": ["asynctest; python_version=='3.7'", "coverage"]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Scientific/Engineering",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Distributed Computing",
        "Topic :: System :: Networking"
    ]
)
