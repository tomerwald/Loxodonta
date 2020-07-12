from neo4j import GraphDatabase


class Neo4jConnector:
    def __init__(self, uri, auth):
        self.connection = GraphDatabase.driver(uri=uri, auth=auth)

    def run_query(self, cypher_command):
        with self.connection.session() as session:
            result = session.run(cypher_command)
            return [x for x in result]

    def load_entity(self, entity):
        return self.run_query(f'merge (a:{entity.entity_type} {{entity_id:"{entity.entity_id}"}}) return id(a)')

    def load_connection(self, connection):
        self.run_query(f'''
            MERGE (a:{connection.side_a.entity_type} {{entity_id:"{connection.side_a.entity_id}"}})
            MERGE (b:{connection.side_b.entity_type} {{entity_id:"{connection.side_b.entity_id}"}})
            MERGE (a)-[:{connection.connection_type}]->(b);
            ''')

    def close(self):
        self.connection.close()
