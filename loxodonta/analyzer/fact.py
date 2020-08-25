from datetime import datetime


def hash_item(item):
    if type(item) == dict:
        return hash_walk_dict(item)
    elif type(item) == list:
        return hash_walk_list(item)
    else:
        return hash(item)


def hash_walk_list(args):
    sum_total = 0
    for i in args:
        sum_total += hash_item(i)
    return sum_total


def hash_walk_dict(kwargs):
    sum_total = 0
    for k, v in kwargs.items():
        sum_total += hash_item(v) + hash_item(k)
    return sum_total


class Entity:
    """
    This object represents any network entity such as MAC, IP, OS etc.
    """
    def __init__(self, entity_type: str, entity_id: str, creation_time: datetime = None):
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.creation_time = creation_time if creation_time else datetime.now()

    def __eq__(self, other):
        return self.entity_type == other.entity_type and self.entity_id == other.entity_id

    def __hash__(self):
        return hash(hash(self.entity_type) + hash(self.entity_type))


class Connection:
    """
    This object represents any network connection such as ARP resolving or TCP traffic
    """
    def __init__(self, connection_type: str, side_a: Entity, side_b: Entity, **kwargs):
        self.connection_type = connection_type
        self.side_a = side_a
        self.side_b = side_b
        self.kwargs = kwargs

    def __eq__(self, other):
        sides_equal = self.side_a == other.side_a and self.side_b == other.side_b
        return self.connection_type == other.connection_type and sides_equal and self.kwargs == other.kwargs

    def __hash__(self):
        kwargs_hash = hash_walk_dict(self.kwargs)
        return hash(hash(self.connection_type) + hash(self.side_a) + hash(self.side_b) + kwargs_hash)
