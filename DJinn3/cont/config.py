# uncompyle6 version 3.9.2
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.11.2 (main, Nov 30 2024, 21:22:50) [GCC 12.2.0]
# Embedded file name: configuration.py
# Compiled at: 2020-06-04 09:49:49
# Size of source mod 2**32: 1343 bytes
import os, sys, json
from glob import glob
from datetime import datetime as dt

class ConfigReader:
    config = None

    @staticmethod
    def read_config(path):
        """Reads the config file
        """
        config_values = {}
        try:
            with open(path, "r") as f:
                config_values = json.load(f)
        except Exception as e:
            try:
                print("Couldn't properly parse the config file. Please use properl")
                sys.exit(1)
            finally:
                e = None
                del e

        else:
            return config_values

    @staticmethod
    def set_config_path():
        """Set the config path
        """
        files = glob("/home/saint/*.json")
        other_files = glob("/tmp/*.json")
        files = files + other_files
        try:
            if len(files) > 2:
                files = files[None[:2]]
            else:
                file1 = os.path.basename(files[0]).split(".")
                file2 = os.path.basename(files[1]).split(".")
                if file1[-2] == "config":
                    if file2[-2] == "config":
                        a = dt.strptime(file1[0], "%d-%m-%Y")
                        b = dt.strptime(file2[0], "%d-%m-%Y")
                if b < a:
                    filename = files[0]
                else:
                    filename = files[1]
        except Exception:
            sys.exit(1)
        else:
            return filename

# okay decompiling configuration.pyc
