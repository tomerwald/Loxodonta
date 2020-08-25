from neo4j import GraphDatabase

from loxodonta.logger import loxo_logger
from loxodonta.analyzer.fact import Entity, Connection


class Neo4jConnector:
    """
    this object will handle to connection, saving and loading of data from the neo4j database
    which acts as the visualization solution for loxodonta
    """

    def __init__(self, uri, auth):
        loxo_logger.info(f"Connecting to: {uri}")
        self.connection = GraphDatabase.driver(uri=uri, auth=auth)

    def run_query(self, cypher_command: str):
        with self.connection.session() as session:
            result = session.run(cypher_command)
            return [x for x in result]

    def load_entity(self, entity: Entity):
        return self.run_query(f'merge (a:{entity.entity_type} {{entity_id:"{entity.entity_id}"}}) return id(a)')

    @staticmethod
    def _parse_kwargs_to_neo4j(connection: Connection, remote_connection):
        params_str = ""
        for k, v in connection.kwargs.items():
            if isinstance(v, str):
                v = f'"{v}"'
            if isinstance(v, list) and k in remote_connection._properties:
                v += remote_connection._properties[k]
                v = list(set(v))
            params_str += f'set p.{k} = {v}\r\n'
        return params_str

    def update_connection_params(self, connection: Connection, remote_connection):
        connection_args = self._parse_kwargs_to_neo4j(connection, remote_connection)
        self.run_query(f'''
            MATCH (a:{connection.side_a.entity_type} {{entity_id:"{connection.side_a.entity_id}"}})
            MATCH (b:{connection.side_b.entity_type} {{entity_id:"{connection.side_b.entity_id}"}})
            MATCH (a)-[p:{connection.connection_type}]->(b)
            {connection_args}
            RETURN p;
            ''')

    def load_connection(self, connection: Connection):
        query_output = self.run_query(f'''
            MERGE (a:{connection.side_a.entity_type} {{entity_id:"{connection.side_a.entity_id}"}})
            MERGE (b:{connection.side_b.entity_type} {{entity_id:"{connection.side_b.entity_id}"}})
            MERGE (a)-[p:{connection.connection_type}]->(b)
            RETURN p;
            ''')
        if connection.kwargs:
            self.update_connection_params(connection, query_output[0][0])

    def close(self):
        self.connection.close()
