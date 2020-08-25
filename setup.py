#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='loxodonta',
    version='0.1.1',
    description='Network traffic visualization',
    author='Tomer Waldmann',
    author_email='tomer.valdman@gmail.com',
    packages=find_packages(exclude=["dev", "dist"]),
    install_requires=['pyshark', 'tqdm', 'neo4j', "click", "appdirs"],
    entry_points={
        'console_scripts': ['loxo_config=loxodonta.cli:loxodonta_config',
                            'loxo=loxodonta.cli:loxo_run']
    }
)
