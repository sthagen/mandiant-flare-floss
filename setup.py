#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import os

import setuptools

requirements = ["pyyaml", "simplejson", "tabulate", "vivisect==0.1.0", "plugnplay", "viv-utils==0.3.17", "enum34"]

# this sets __version__
# via: http://stackoverflow.com/a/7071358/87207
# and: http://stackoverflow.com/a/2073599/87207
with open(os.path.join("floss", "version.py"), "r") as f:
    exec(f.read())


# via: https://packaging.python.org/guides/making-a-pypi-friendly-readme/
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, "README.md"), "r") as f:
    long_description = f.read()


setuptools.setup(
    name="flare-floss",
    version=__version__,
    description="FLARE Obfuscated String Solver",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Willi Ballenthin, Moritz Raabe",
    author_email="william.ballenthin@mandiant.com, moritz.raabe@mandiant.com",
    url="https://www.github.com/fireeye/flare-floss",
    packages=[
        "floss",
        "floss.plugins",
    ],
    package_dir={"floss": "floss"},
    entry_points={
        "console_scripts": [
            "floss=floss.main:main",
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest",
            "pytest-sugar",
            "pytest-instafail",
            "pytest-cov",
        ]
    },
    zip_safe=False,
    keywords="floss",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python :: 2.7",
    ],
)
