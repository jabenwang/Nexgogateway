#!/usr/bin/env python
# coding=utf-8

from setuptools import setup, find_packages

setup(
    name="Pynexbang",
    version="1.0",
    description="nexbang hub sdk",
    license="MIT Licence",

    url="http://www.nexgo.com",
    author="bingo",
    author_email="jabenwang@gmail.com",

    package_dir={'Pynexbang': 'src'},
    packages=["Pynexbang"],
    platforms="any",
    install_requires=[],

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Home Automation',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
