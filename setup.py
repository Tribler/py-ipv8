from setuptools import find_packages, setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pyipv8',
    author='Tribler',
    description='The Python implementation of the IPV8 library',
    long_description=long_description,
    long_description_content_type='text/markdown',
    version='1.9.0',
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
        "pyasn1"
    ],
    extras_require={
        'netifaces': ["netifaces"]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Scientific/Engineering",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Distributed Computing",
        "Topic :: System :: Networking"
    ]
)
