import functools

import click
import pyshark
import tqdm

from loxodonta.analyzer import Analyzer
from loxodonta.analyzer.application import all as application_protocols
from loxodonta.analyzer.data_link import all as data_link_protocols
from loxodonta.analyzer.transport import all as transport_protocols
from loxodonta.analyzer.network import all as network_protocols

from loxodonta.analyzer.fact import Entity, Connection
from loxodonta.config import LoxoConfig
from loxodonta.data_loader.loader import Neo4jConnector
from loxodonta.logger import loxo_logger


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


def _parse_layer_analyzers(data_link, transport, network, application):
    analyzers = []
    analyzers += data_link_protocols if data_link else []
    analyzers += transport_protocols if transport else []
    analyzers += network_protocols if network else []
    analyzers += application_protocols if application else []
    return Analyzer(*analyzers)


def _save_facts(connector, facts):
    unique_facts = set(facts)
    for f in tqdm.tqdm(unique_facts, unit="Fact"):
        if type(f) == Connection:
            connector.load_connection(f)
        elif type(f) == Entity:
            connector.load_entity(f)


@click.command()
@click.argument("pcap_path")
@click.option("--data-link", '-d', is_flag=True, default=False, help="digest datalink layer packets")
@click.option("--transport", '-t', is_flag=True, default=False, help="digest transport layer packets")
@click.option("--network", '-n', is_flag=True, default=False, help="digest network layer packets")
@click.option("--application", '-a', is_flag=True, default=False, help="digest application layer packets")
def loxo_run(pcap_path, **layer_options):
    config = LoxoConfig()
    neo4j_connector = Neo4jConnector(config.config["neo4j_url"],
                                     auth=(config.config["neo4j_username"], config.config["neo4j_password"]))
    analyzer = _parse_layer_analyzers(**layer_options)
    try:
        with pyshark.FileCapture(pcap_path) as cap:
            facts = functools.reduce(lambda x, y: x + y, [x for x in analyzer.analyze_file_capture(cap)])
        loxo_logger.info("Saving facts")
        _save_facts(neo4j_connector, facts)
    except pyshark.capture.capture.TSharkCrashException as e:
        loxo_logger.error(e)
    finally:
        neo4j_connector.close()
