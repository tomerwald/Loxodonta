import json
import os

import appdirs

from loxodonta.logger import loxo_logger

DEFAULT_CONFIG = {
    "neo4j_url": "bolt://127.0.0.1:7687",
    "neo4j_username": "neo4j",
    "neo4j_password": "neo4j"
}


class LoxoConfig(object):
    def __init__(self):
        self.config_file_path = os.path.join(appdirs.user_config_dir("loxodonta"), "loxodonta_config.json")
        self._initiate_config_file()
        self.config = dict()
        self._load_config()

    def _initiate_config_file(self):
        os.makedirs(os.path.dirname(self.config_file_path), exist_ok=True)
        if not os.path.exists(self.config_file_path):
            with open(self.config_file_path, "w") as new_config:
                loxo_logger.info("Initiating config file")
                json.dump(DEFAULT_CONFIG, new_config)

    def _load_config(self):
        with open(self.config_file_path, 'r') as config_file:
            self.config = json.load(config_file)

    def save_config(self):
        with open(self.config_file_path, 'w') as config_file:
            json.dump(self.config, config_file)

    def __repr__(self):
        return json.dumps(self.config, indent=4, sort_keys=True)
