from setuptools import Extension, setup


setup(ext_modules=[Extension('unpack._hook_filter', ['unpack/_hook_filter.c'], optional=True)])
