import os
import configparser
import logging

CRIU_PATH = '/var/tmp/criu/'

class ExtraConfig():
    def __init__(self):
        if not os.path.exists(CRIU_PATH):
            os.makedirs(CRIU_PATH)
        self.config = configparser.ConfigParser()
    
    def mkdir(self, path, img_work):
        if path[-1] == '/':
            path = path[:-1]
        if not os.path.exists(path):
            os.makedirs(path)
            if img_work:
                logging.debug(f"Creating imgs_dir and work_dir in {path}")
                os.makedirs(path + '/imgs_dir')
                os.makedirs(path + '/work_dir')
    
    def writeConfig(self, path, config):
        with open(path, 'w') as f:
            f.write("[criu]\n")
            for key, value in config["criu"].items():
                f.write(str(key) + "=" + str(value) + "\n")
    
    def readConfig(self, path):
        self.config.read(path)
        return self.config

    









