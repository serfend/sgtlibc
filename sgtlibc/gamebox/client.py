from .config import GameBoxConfig
from sgtpyutils.logger import logger
from typing import Tuple
import pwn
import os
import sys
client: pwn.tube = None
is_local: bool = False
tube_file: str = None
tube_remote: Tuple = None


def set_config(config: GameBoxConfig = None):
    '''
    configure setting of game-box
    '''
    if not config:
        config = GameBoxConfig()
        logger.warning(f'config not specify , initialize with {config}')
    else:
        logger.info(f'config been set to :{config}')
    global tube_file
    tube_file = config.file
    global tube_remote
    tube_remote = config.tube_remote
    global is_local
    is_local = config.is_local
    global client
    client = None
    pwn.context.log_level = config.log_level
    pwn.context.os = config.os
    pwn.context.arch = config.arch


def check_client():
    global client
    '''
    check if client (remote/local) is available
    '''
    if not client:
        client = start_game()
        if not client:
            logger.error('client not available')
            sys.exit(0)
    return client


def start_game():
    global is_local
    local = is_local
    if local:
        global tube_file
        os.system(f'chmod 777 {tube_file}')
        return pwn.process(tube_file)
    else:
        global tube_remote
        return pwn.remote(tube_remote[0], tube_remote[1])
