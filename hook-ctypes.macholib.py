#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: hook-ctypes.macholib.py
Author: YJ
Email: yj1516268@outlook.com
Created Time: 2020-12-07 13:25:19

Description:
"""

from PyInstaller.utils.hooks import copy_metadata

datas = copy_metadata('prettytable')
