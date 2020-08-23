#!/usr/bin/env python

from distutils.core import setup

setup(
    name='loxodonta',
    version='0.1.0',
    description='Network traffic visualization',
    author='Tomer Waldmann',
    author_email='tomer.valdman@gmail.com',
    packages=['loxodonta'],
    install_requires=['pyshark', 'tqdm', 'neo4j', "click", "appdirs"],
    entry_points='''
            [console_scripts]
            loxo_config=loxodonta:loxodonta_config
        '''
)
