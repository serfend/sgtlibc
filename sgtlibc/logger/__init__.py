import logging
import logging.handlers
import colorlog
logger = logging.getLogger('common')  # 获取名为commomn的logger。
LOG_FILE = 'log.log'


def redefine_level_name():
    from logging import CRITICAL, FATAL, ERROR, WARNING, WARN, INFO, DEBUG, NOTSET
    dic = {
        CRITICAL: '!!',
        FATAL: '!!',
        ERROR: '-',
        WARNING: '!',
        WARN: '!',
        INFO: '+',
        DEBUG: '*',
        NOTSET: '~',
    }
    for i in dic:
        logging.addLevelName(i, dic[i])

redefine_level_name()
fmt = '%(asctime)s [%(levelname)s] %(message)s :%(filename)s:%(lineno)s-%(levelno)s  %(pathname)s on(%(module)s.%(funcName)s) at %(process)d@%(threadName)s  '  # 定义日志格式
handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=1024*1024, backupCount=5)
formatter = logging.Formatter(fmt)   # 实例化formatter。
handler.setFormatter(formatter)      # 为handler添加formatter。
logger.addHandler(handler)           # 为logger添加handler。

fmt = '%(asctime)s [%(levelname)s] %(message)s'  # 定义日志格式
from colorlog.escape_codes import escape_codes_foreground
colors = {
    '*': 'light_blue',
    '+': 'green',
    '!': 'yellow',
    '-': 'red',
    '!!': 'purple,bg_white',
}
fmt_colored = colorlog.ColoredFormatter(
    f'%(log_color)s{fmt}', datefmt=None, reset=True, log_colors=colors)
handler = logging.StreamHandler()
handler.setFormatter(fmt_colored)      # 为handler添加formatter。
logger.addHandler(handler)           # 为logger添加handler。


logger.setLevel(logging.DEBUG)