# -*- coding: utf-8 -*-
import logging
import webbrowser
from http.client import HTTPConnection
from time import sleep

from .utils import ConfigMan


def url_ok(url: str, port: int, logger: logging.Logger) -> bool:
    try:
        conn = HTTPConnection(url, port)
        conn.request('GET', '/')
        r = conn.getresponse()
        return r.status == 200
    except:
        logger.exception('Server not started')
        return False


def main() -> None:
    logger = logging.getLogger(__name__)
    cfg = ConfigMan()
    port = cfg.get_localport()
    time = 0
    while True:
        if not port:
            port = cfg.get_localport()
        elif url_ok('127.0.0.1', port, logger) or time == 5:
            break
        sleep(1)
        time += 1

    url = 'http://127.0.0.1:{}'.format(port)
    webbrowser.open(url)
