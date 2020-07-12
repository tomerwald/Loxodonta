from datetime import datetime


class Entity:
    Overrideable = True

    def __init__(self, entity_id, creation_time=None):
        self.entity_id = entity_id
        self.creation_time = creation_time if creation_time else datetime.now()


class Connection:
    Overrideable = True

    def __init__(self, side_a, side_b):
        self.side_a = side_a
        self.side_a = side_b
