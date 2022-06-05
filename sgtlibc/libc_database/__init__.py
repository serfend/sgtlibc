import os
from .. import logger


def install():
    logger.info('start check requirements')
    cmd = '''
    apt-get update
    apt-get install -y \
      binutils file \
      wget \
      rpm2cpio cpio \
      zstd jq
    '''
    os.system(cmd)


def update():
    if os.name == 'nt':
        return logger.error('update database should run on non-microsoft-windows system , like ubuntu etc.')
    install()
    logger.info('start downloading')
    os.system('./libc-database/get ubuntu debian centos kali arch alpine parrotsec launchpad')
