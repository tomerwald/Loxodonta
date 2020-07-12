from datetime import datetime


class Entity:
    def __init__(self, entity_type, entity_id, creation_time=None):
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.creation_time = creation_time if creation_time else datetime.now()

    def __eq__(self, other):
        return self.entity_type == other.entity_type and self.entity_id == other.entity_id

    def __hash__(self):
        return hash(hash(self.entity_type) + hash(self.entity_type))


class Connection:
    def __init__(self, connection_type, side_a, side_b):
        self.connection_type = connection_type
        self.side_a = side_a
        self.side_b = side_b

    def __eq__(self, other):
        sides_equal = self.side_a == other.side_a and self.side_b == other.side_b
        return self.connection_type == other.connection_type and sides_equal

    def __hash__(self):
        return hash(hash(self.connection_type) + hash(self.side_a) + hash(self.side_b))
