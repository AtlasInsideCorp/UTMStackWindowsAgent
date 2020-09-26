# -*- coding: utf-8 -*-
from http.client import HTTPConnection
from time import sleep
import os
import sys
import logging
import webbrowser

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, 'libs'))
import utm_stack


logger = logging.getLogger(__name__)


def url_ok(url: str, port: int) -> bool:
    try:
        conn = HTTPConnection(url, port)
        conn.request('GET', '/')
        r = conn.getresponse()
        return r.status == 200
    except:
        logger.exception('Server not started')
        return False


if __name__ == '__main__':
    cfg = utm_stack.ConfigMan()
    port = cfg.get_localport()
    time = 0
    while True:
        if not port:
            port = cfg.get_localport()
        elif url_ok('127.0.0.1', port) or time == 5:
            break
        sleep(1)
        time += 1

    url = 'http://127.0.0.1:{}'.format(port)
    webbrowser.open(url)
