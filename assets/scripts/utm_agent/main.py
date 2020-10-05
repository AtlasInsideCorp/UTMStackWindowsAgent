import argparse
import logging
import webbrowser
from http.client import HTTPConnection
from time import sleep

from . import __version__
from .api import install_antivirus, update_settings
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


def open_gui(port: int, logger: logging.Logger) -> None:
    time = 0
    while True:
        if url_ok('127.0.0.1', port, logger) or time == 5:
            break
        sleep(1)
        time += 1

    url = 'http://127.0.0.1:{}'.format(port)
    webbrowser.open(url)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--version",
                        help="show program's version number",
                        action="version", version=__version__)
    parser.add_argument("--gui",
                        help="Launch program's GUI",
                        action="store_true")
    parser.add_argument("--reset",
                        help="Reset program's configuration",
                        action="store_true")
    parser.add_argument("--host",
                        help="Set probe host address")
    parser.add_argument("--acl",
                        help="Enable or disable sending of acl data",
                        choices=('yes', 'no'))
    parser.add_argument("--antivirus",
                        help="Install antivirus with the given license key")

    args = parser.parse_args()

    logger = logging.getLogger(__name__)
    cfg = ConfigMan()

    if args.reset:
        cfg.delete_data()
    if args.host:
        update_settings(args.host)
    if args.acl:
        if args.acl == 'yes':
            cfg.set_acls_time(0)
            cfg.set_acl_check(True)
        else:
            cfg.set_acl_check(False)
    if args.antivirus:
        install_antivirus(args.antivirus)
    if args.gui:
        open_gui(cfg.get_localport(), logger)
