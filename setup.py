#!/usr/bin/python3
"""
setup.py

This is to build an installer for the command-line tool zmodem,
using cx_Freeze.

To build an installer:

    setup.py bdist_msi
"""

import sys
from cx_Freeze import setup, Executable

import zmodem.version

includefiles = [ ]
includes = [ 'zmodem', 'zmodem.loghandlers', ]
excludes = [ 'tkinter', 'test', 'unittest', 'xml', ]
packages = [ 'colorlog', ]

setup(
    name="ZMODEM",
    description="ZMODEM send and receive",
    version=zmodem.version.__version__,
    author="Craig McQueen",
    options = {
        'build_exe': {
            'includes': includes,
            'excludes': excludes,
            'packages': packages,
            'include_files': includefiles,
            'replace_paths': [("*", "")],
        },
        'bdist_msi': {
            'add_to_path': True,
            'upgrade_code': '{413c69ba-0476-4121-8280-745bc8d605cf}',
            'initial_target_dir': '[ProgramFilesFolder]\\zmodem-py\\',
        },
    },
    executables = [
        Executable("zmodem.py", copyright="Copyright (C) 2024 Craig McQueen"),
    ],
)
