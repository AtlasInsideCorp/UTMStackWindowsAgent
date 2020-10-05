# -*- coding: utf-8 -*-
import logging.handlers
import os
import sqlite3
import subprocess
from enum import IntEnum


class Command(IntEnum):
    SHUTDOWN_SERVER = 1    # 1. shutdown server
    DISABLE_USER = 2       # 2. kick out and disable user
    BLOCK_IP = 3           # 3. block ip and disconnect any traffic from IP
    ISOLATE_HOST = 4       # 4. Isolate host (disconnect from network)
    RESTART_SERVER = 5     # 5. restart server
    KILL_PROCESS = 6       # 6. kill process
    UNINSTALL_PROGRAM = 7  # 7. uninstall program
    RUN_CMD = 8            # 8. run shell command


class ServiceStatus(IntEnum):
    UNINSTALLED = -1
    STOPPED = 0
    RUNNING = 1


class ConfigMan():
    def __init__(self) -> None:
        self.app_dir = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        self.filebeat_dir = os.path.join(self.app_dir, 'Filebeat')
        self.metricbeat_dir = os.path.join(self.app_dir, 'Metricbeat')
        self.winlogbeat_dir = os.path.join(self.app_dir, 'Winlogbeat')
        self.hids_dir = r'C:\Program Files (x86)\ossec-agent'
        self.db = ConfigDB(os.path.join(self.app_dir, 'appdata.db'))

    def set_localport(self, port: int) -> None:
        self.db.set('local_port', port)

    def get_localport(self) -> int:
        return int(self.db.get('local_port') or 23948)

    def set_probeport(self, port: int) -> None:
        self.db.set('probe_port', port)

    def get_probeport(self) -> int:
        return int(self.db.get('probe_port') or 23949)

    def set_winlog_small(self, is_small: bool) -> None:
        self.db.set('winlog_small', 1 if is_small else 0)

    def get_winlog_small(self) -> bool:
        return self.db.get('winlog_small') == '1'

    def set_ps_old(self, is_old: bool) -> None:
        self.db.set('ps_old', 1 if is_old else 0)

    def get_ps_old(self) -> bool:
        return self.db.get('ps_old') == '1'

    def set_ip(self, ip: str) -> None:
        self.db.set('server_ip', ip)

    def get_ip(self) -> str:
        return self.db.get('server_ip')

    def set_last_check_for_updates(self, timestamp: float) -> None:
        self.db.set('last_check_for_updates', timestamp)

    def get_last_check_for_updates(self) -> float:
        return float(self.db.get('last_check_for_updates') or 0)

    def set_pcs_time(self, timestamp: float) -> None:
        self.db.set('pcs_last_timestamp', timestamp)

    def get_pcs_time(self) -> float:
        return float(self.db.get('pcs_last_timestamp') or 0)

    def set_swl_time(self, timestamp: float) -> None:
        self.db.set('swl_last_timestamp', timestamp)

    def get_swl_time(self) -> float:
        return float(self.db.get('swl_last_timestamp') or 0)

    def set_acls_time(self, timestamp: float) -> None:
        self.db.set('acls_last_timestamp', timestamp)

    def get_acls_time(self) -> float:
        return float(self.db.get('acls_last_timestamp') or 0)

    def set_acl_check(self, check: bool) -> None:
        self.db.set('acl_check', 1 if check else 0)

    def get_acl_check(self) -> bool:
        return self.db.get('acl_check') == '1'

    def set_agent_id(self, agent_id: str) -> None:
        self.db.set('agent_id', agent_id)

    def get_agent_id(self) -> str:
        return self.db.get('agent_id')

    def set_wazuh_key(self, wazuh_key: str) -> None:
        self.db.set('wazuh_key', wazuh_key)

    def get_wazuh_key(self) -> str:
        return self.db.get('wazuh_key')

    def add_filebeat_input(self, path: str, field: str) -> bool:
        q = 'INSERT INTO filebeat_inputs VALUES (?,?)'
        try:
            self.db.commit(q, (path, field))
            return True
        except sqlite3.IntegrityError:
            return False

    def del_filebeat_input(self, path: str) -> None:
        self.db.commit(
            'DELETE FROM filebeat_inputs WHERE path=?',
            (path,))

    def get_filebeat_inputs(self) -> list:
        return self.db.execute(
            'SELECT * FROM filebeat_inputs').fetchall()

    def add_jobs(self, jobs: list) -> None:
        for job_id, cmd_id, params in jobs:
            self.db.commit('INSERT INTO jobs VALUES (?,?,?)',
                           (job_id, cmd_id, params))

    def remove_job(self, job_id: int) -> None:
        self.db.commit('DELETE FROM jobs WHERE id=?', (job_id,))

    def get_jobs(self) -> list:
        return self.db.execute('SELECT * FROM jobs').fetchall()

    def delete_data(self) -> None:
        self.db.delete_tables()


class ConfigDB:
    def __init__(self, db_path: str) -> None:
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self.create_tables()
        version = self.get('db_version')
        if not version:
            self.set('db_version', '1')

    def execute(self, statement: str, args=()) -> sqlite3.Cursor:
        return self._db.execute(statement, args)

    def commit(self, statement: str, args=()) -> None:
        with self._db:
            self._db.execute(statement, args)

    def set(self, key: str, value) -> None:
        self.commit(
            'INSERT OR REPLACE INTO config VALUES (?,?)', (key, value))

    def get(self, key: str) -> str:
        r = self.execute(
            'SELECT * FROM config WHERE key=?', (key,)).fetchone()
        return r['value'] if r else ''

    def close(self) -> None:
        self._db.close()

    def create_tables(self) -> None:
        with self._db:
            self._db.execute('''CREATE TABLE IF NOT EXISTS config
                               (key TEXT PRIMARY KEY,
                                value TEXT)''')
            self._db.execute('''CREATE TABLE IF NOT EXISTS filebeat_inputs
                               (path TEXT PRIMARY KEY,
                                field TEXT)''')
            self._db.execute('''CREATE TABLE IF NOT EXISTS jobs
                               (id INTEGER PRIMARY KEY,
                                cmd_id INTEGER,
                                params TEXT)''')

    def delete_tables(self) -> None:
        with self._db:
            self._db.execute('DROP TABLE config')
            self._db.execute('DROP TABLE filebeat_inputs')
            self._db.execute('DROP TABLE jobs')


def get_logger(name: str) -> logging.Logger:
    logdir = r'C:\ProgramData\UTMStack\logs'

    if not os.path.exists(logdir):
        os.makedirs(logdir)

    logger = logging.Logger(name)
    logger.parent = None  # type: ignore
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s')

    chandler = logging.StreamHandler()
    chandler.setLevel(logging.DEBUG)
    chandler.setFormatter(formatter)
    logger.addHandler(chandler)

    log_path = os.path.join(logdir, 'log-{}.txt'.format(name))
    fhandler = logging.handlers.RotatingFileHandler(
        log_path, backupCount=3, maxBytes=2000000)
    fhandler.setLevel(logging.INFO)
    fhandler.setFormatter(formatter)
    logger.addHandler(fhandler)
    logger.log_path = log_path  # type: ignore

    return logger


def run_cmd(cmd: tuple, **kwargs) -> str:
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.STDOUT
    kwargs['text'] = True
    kwargs['check'] = True
    return subprocess.run(cmd, **kwargs).stdout


def ps(cmd: str) -> str:
    return run_cmd(('powershell', '-NoProfile', '-Command', cmd))
