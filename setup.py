#!/usr/bin/python
#-*- coding: utf-8 -*-

from distutils.core import setup, Extension

import os
import sys
prefix = os.environ.get("prefix", "/usr")

from distutils.core import setup, Extension
import subprocess as S

setup(name="polkit",
      version="1.0.2",
      description="Python bindings for polkit-1",
      long_description="Python bindings for polkit-1",
      license="GNU GPL2",
      author="Bahadır Kandemir",
      author_email="bahadir@pardus.org.tr",
      url="http://github.com/Pardus-Linux/python-polkit/",
      py_modules = ["polkit"],
      ext_modules = [Extension('_polkit',
                               sources=['pypolkit.c'],
                               include_dirs=["/usr/include/polkit-1", "/usr/include/glib-2.0", "/usr/lib/glib-2.0/include"],
                               libraries=["polkit-gobject-1", "gio-2.0", "gobject-2.0", "gmodule-2.0", "gthread-2.0", "pthread", "rt", "glib-2.0"],
                               library_dirs=[],
                               )],
      )
