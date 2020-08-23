import click
import functools

import pyshark
import tqdm

from loxodonta.analyzer import Analyzer
# from loxodonta.analyzer.application import HTTP, DNS, SSH, HTTPS, SMB
from loxodonta.analyzer.data_link import Ethernet, ARP
from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.data_loader.loader import Neo4jConnector
from loxodonta.logger import loxo_logger
import os
from loxodonta.config import LoxoConfig


@click.command()
@click.option("--neo4j-url", '-i', default=None, help="neo4j database url")
@click.option("--neo4j-username", '-u', default=None, help="neo4j username (DEFAULT: neo4j)")
@click.option("--neo4j-password", '-p', default=None, help="neo4j password (DEFAULT: neo4j)")
@click.option("--verbose", '-v', is_flag=True, default=False, help="Print the current configuration")
def loxodonta_config(verbose, **kwargs):
    conf = LoxoConfig()
    updates = {k: v for k, v in kwargs.items() if v is not None}
    conf.config.update(updates)
    conf.save_config()
    if verbose:
        print(conf)
