#!/usr/bin/env python

from distutils.core import setup

setup(
    name='loxodonta',
    version='0.0.2',
    description='Network traffic visualization',
    author='Tomer Waldmann',
    author_email='tomer.valdman@gmail.com',
    packages=['loxodonta'],
    install_requires=['pyshark', 'tqdm', 'neo4j']
)
