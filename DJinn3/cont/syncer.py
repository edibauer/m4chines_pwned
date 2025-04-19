# uncompyle6 version 3.9.2
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.11.2 (main, Nov 30 2024, 21:22:50) [GCC 12.2.0]
# Embedded file name: syncer.py
# Compiled at: 2020-06-01 06:32:59
# Size of source mod 2**32: 587 bytes
from configuration import *
from connectors.ftpconn import *
from connectors.sshconn import *
from connectors.utils import *

def main():
    """Main function
    Cron job is going to make my work easy peasy
    """
    configPath = ConfigReader.set_config_path()
    config = ConfigReader.read_config(configPath)
    connections = checker(config)
    if "FTP" in connections:
        ftpcon(config["FTP"])
    else:
        if "SSH" in connections:
            sshcon(config["SSH"])
        else:
            if "URL" in connections:
                sync(config["URL"], config["Output"])


if __name__ == "__main__":
    main()

# okay decompiling syncer.pyc
