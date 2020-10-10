# -*- coding: utf-8 -*-
import io
import json
import logging
import os
import socket
import time
import winreg
from subprocess import CalledProcessError, TimeoutExpired
from threading import Event, Thread
from typing import Any, Dict, List
from zipfile import ZipFile

import requests

from . import __version__
from .api import get_status, run_api, update_wazuh
from .utils import Command, ConfigMan, get_logger, pshell, run_cmd

cfg = ConfigMan()
shutdown = Event()
logger = get_logger('service')
fsr = {
    "1179785": "Read",
    "1179817": "ReadAndExecute",
    "1180063": "Read, Write",
    "1180095": "ReadAndExecute, Write",
    "1245631": "ReadAndExecute, Modify, Write",
    "2032127": "FullControl",
    "268435456": "FullControl (Sub Only)",
    "536870912": "GENERIC_EXECUTE",
    "1073741824": "GENERIC_WRITE",
    "2147483648": "GENERIC_READ",
    "-536805376": "Modify, Synchronize",
    "-1610612736": "ReadAndExecute, Synchronize"}


class AgentClient:
    def __init__(self):
        self.jobs_delay = 15
        self.stats_delay = 60*4
        self.srv_port = cfg.get_probeport()
        self.agent_id = None
        self.ip_addr = None

    def api_call(self, req: str, **kwargs):
        url = 'http://{}:{}/{}'.format(
            self.ip_addr, self.srv_port, req)
        kwargs['agent_id'] = self.agent_id
        raw = kwargs.pop('raw', False)
        with requests.post(url, kwargs) as resp:
            resp.raise_for_status()
            if raw:
                return resp.content
            response = resp.json()
        if response['error'] == 2:  # Agent not registered
            cfg.set_agent_id('')
        return response

    def register_agent(self) -> None:
        self.agent_id = socket.gethostname()
        resp = self.api_call('register_agent')
        wazuh_key, self.agent_id = resp['key'], resp['agent_id']
        cfg.set_wazuh_key(wazuh_key)
        cfg.set_agent_id(self.agent_id)
        update_wazuh(self.ip_addr, wazuh_key)

    def check_for_updates(self) -> None:
        data = self.api_call(
            'get_update', agent_version=__version__, raw=True)
        cfg.set_last_check_for_updates(time.time())
        if data:
            with io.BytesIO(data) as file:
                with ZipFile(file) as zfile:
                    zfile.extractall(cfg.app_dir)
            shutdown.set()

    def _check_for_updates(self) -> None:
        last_checked = cfg.get_last_check_for_updates()
        last_checked = (time.time() - last_checked)/3600
        if last_checked >= 1:
            logger.info('Checking for app updates.')
            try:
                self.check_for_updates()
                if not shutdown.is_set():
                    logger.info('There are no app updates.')
            except Exception as ex:
                logger.error(
                    'Failed checking for updates: %s', ex)

    def _process_tasks(self) -> None:
        logger.info('Requesting tasks to probe server.')
        try:
            jobs = self.api_call('get_jobs')['jobs']
            cfg.add_jobs(jobs)
            jobs = cfg.get_jobs()
            for job_id, cmd_id, params in jobs:
                cfg.remove_job(job_id)
                res = _run_job(cmd_id, params)
                data = {'job_id': job_id,
                        'result': json.dumps(res)}
                self.api_call('set_job_result', **data)
            if not jobs:
                logger.info('There are not new tasks.')
        except (ConnectionError,
                requests.ConnectionError,
                requests.HTTPError):
            logger.info(
                'Failed to get tasks from probe server (%s)', self.ip_addr)

    def start_jobs_worker(self) -> None:
        while not shutdown.is_set():
            try:
                if self.ip_addr and cfg.get_agent_id():
                    self._check_for_updates()
                    self._process_tasks()
            except Exception:
                logger.exception('Unexpected error on the tasks thread')
            shutdown.wait(self.jobs_delay)

    def _register_agent(self) -> None:
        try:
            self.register_agent()
            logger.info('Agent registered on probe server: %s', self.ip_addr)
        except (ConnectionError,
                requests.ConnectionError,
                requests.HTTPError):
            self.agent_id = None
            logger.exception(
                'Failed to register Agent on probe server: %s', self.ip_addr)

    def _send_computer_status(self) -> None:
        last_sent = cfg.get_pcs_time()
        time_elapsed = (time.time() - last_sent)/3600
        if time_elapsed >= 24:
            try:
                logger.info(
                    'Sending computer status to server.')
                self.api_call(
                    'computer_status', status=json.dumps(computer_stats()))
                cfg.set_pcs_time(time.time())
            except CalledProcessError as ex:
                logger.exception(
                    'Failed to send computer status to server %s: %s',
                    self.ip_addr, ex.stdout)
            except (ConnectionError,
                    requests.ConnectionError,
                    requests.HTTPError):
                logger.exception(
                    'Failed to send computer status to server %s',
                    self.ip_addr)

    def _send_software_list(self) -> None:
        last_sent = cfg.get_swl_time()
        time_elapsed = (time.time() - last_sent)/3600
        if time_elapsed >= 24:
            try:
                logger.info('Sending software list to server.')
                self.api_call(
                    'software_status',
                    status=json.dumps(list_installed_software()))
                cfg.set_swl_time(time.time())
            except CalledProcessError as ex:
                logger.exception(
                    'Failed to send software list to server %s: %s',
                    self.ip_addr, ex.stdout)
            except (ConnectionError,
                    requests.ConnectionError,
                    requests.HTTPError):
                logger.exception(
                    'Failed to send software list to server: %s',
                    self.ip_addr)

    def _send_user_list(self) -> None:
        acl_enabled = cfg.get_acl_check()
        last_sent = cfg.get_acls_time()
        time_elapsed = (time.time() - last_sent)/3600
        if acl_enabled and time_elapsed >= 24:
            try:
                logger.info('Requesting users list.')
                users = self.api_call(
                    'get_ldap_users')['users']
                logger.info(
                    'Sending ACLs stats to server.')
                self.api_call(
                    'acls_status',
                    status=json.dumps(acls_stats(users)))
                cfg.set_acls_time(time.time())
            except CalledProcessError as ex:
                logger.exception(
                    'Failed to send ACLs stats to server %s: %s',
                    self.ip_addr, ex.stdout)
            except (ConnectionError,
                    requests.ConnectionError,
                    requests.HTTPError):
                logger.exception(
                    'Failed to send ACLs stats to server: %s',
                    self.ip_addr)

    def _send_agent_status(self) -> None:
        logger.info('Sending agent status to probe server.')
        data = get_status()
        data['agent_version'] = __version__
        try:
            self.api_call('update_status', **data)
        except (ConnectionError,
                requests.ConnectionError,
                requests.HTTPError):
            logger.exception('Failed to send agent status to probe server: %s',
                             self.ip_addr)

    def start_stats_worker(self) -> None:
        while not shutdown.is_set():
            _check_winlogs_limit()
            _check_ps_version()
            try:
                self.ip_addr = cfg.get_ip()
                if self.ip_addr:
                    self.agent_id = cfg.get_agent_id()
                    if not self.agent_id:
                        logging.info(
                            'Agent is not registered on probe server'
                            ' (%s), registering now.', self.ip_addr)
                        self._register_agent()
                        if not self.agent_id:
                            shutdown.wait(10)
                            continue

                    self._send_agent_status()
                    self._send_computer_status()
                    self._send_software_list()
                    self._send_user_list()
                else:
                    logger.warning('Probe server IP not configured.')
            except Exception:
                logger.exception('Unexpected error on the status thread')
            if cfg.get_agent_id():
                shutdown.wait(self.stats_delay)
            else:
                shutdown.wait(10)

    def run(self) -> None:
        # Start Flask server
        logger.info('Starting GUI server.')
        thread = Thread(target=run_api, daemon=True)
        thread.start()

        # Check for jobs
        logger.info('Starting tasks thread.')
        thread = Thread(target=self.start_jobs_worker, daemon=True)
        thread.start()

        # Send status
        logger.info('Starting status thread.')
        thread = Thread(target=self.start_stats_worker, daemon=True)
        thread.start()

        shutdown.wait()


def block_ip(ip_addr, direction):
    cmd = ('netsh', 'advfirewall', 'firewall',
           'add', 'rule', f'name="UTMS_Block_{ip_addr}"',
           f'dir={direction}', 'interface=any',
           'action=block', f'remoteip={ip_addr}')
    return run_cmd(cmd)


def disable_interface(interface):
    cmd = ('netsh', 'interface', 'set', 'interface',
           interface, 'admin=disable')
    return run_cmd(cmd, timeout=30)


def _get_soft(hive, flag) -> list:
    a_reg = winreg.ConnectRegistry(None, hive)
    try:
        rpath = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        a_key = winreg.OpenKey(
            a_reg, rpath, 0, winreg.KEY_READ | flag)
    except FileNotFoundError:
        return []

    software_list = []

    count_subkey = winreg.QueryInfoKey(a_key)[0]

    for i in range(count_subkey):
        software = {}
        try:
            asubkey_name = winreg.EnumKey(a_key, i)
            asubkey = winreg.OpenKey(a_key, asubkey_name)
            software['name'] = winreg.QueryValueEx(
                asubkey, "DisplayName")[0]

            try:
                software['version'] = winreg.QueryValueEx(
                    asubkey, "DisplayVersion")[0]
            except EnvironmentError:
                software['version'] = None

            try:
                software['publisher'] = winreg.QueryValueEx(
                    asubkey, "Publisher")[0]
            except EnvironmentError:
                software['publisher'] = None

            software_list.append(software)
        except EnvironmentError:
            continue

    return software_list


def list_installed_software() -> list:
    software_list = _get_soft(winreg.HKEY_LOCAL_MACHINE,
                              winreg.KEY_WOW64_32KEY)
    software_list.extend(_get_soft(winreg.HKEY_LOCAL_MACHINE,
                                   winreg.KEY_WOW64_64KEY))
    software_list.extend(_get_soft(winreg.HKEY_CURRENT_USER, 0))
    return software_list


def acls_stats(users: List[dict]) -> list:
    cmd = 'return ((Get-ACL "AD:$((Get-ADUser %s)'
    cmd += '.distinguishedname)").access | where'
    cmd += '{$_.identityreference -notmatch "BUILTIN|'
    cmd += 'NT AUTHORITY|EVERYONE|CREATOR OWNER"}) |'
    cmd += 'Out-String -width 2048'

    keys = ['ActiveDirectoryRights', 'InheritanceType', 'ObjectType',
            'InheritedObjectType', 'ObjectFlags', 'AccessControlType',
            'IdentityReference', 'IsInherited', 'InheritanceFlags']

    acls = []
    for elem in users:
        try:
            lines = pshell(
                cmd % (elem['sAMAccountName'],)).strip().splitlines()
            user = {}
            user["objectSid"] = str(elem["objectSid"])
            acl_group = []
            acl = {}
            for line in map(str.strip, lines):
                if not line:
                    continue
                key, val = map(str.strip, line.split(' : '))
                if key in keys:
                    acl[key] = val
                elif key == 'PropagationFlags':
                    acl[key] = val
                    acl_group.append(acl)
                    acl = {}
            user["userACLs"] = acl_group
            acls.append(user)
        except Exception:
            logger.warning(
                'Failed to get ACL info for user %s',
                elem['sAMAccountName'])
            continue
    return acls


def _get_sid() -> str:
    host_name = socket.gethostname()
    cmd = '$ID = (new-object System.Security.Principal.NTAccount("'
    cmd += host_name + '$"))\n'
    ident = '[System.Security.Principal.SecurityIdentifier]'
    cmd += f'return $ID.Translate( {ident} ).toString()'
    return pshell(cmd).strip()


def _get_ip_list() -> List[dict]:
    ip_list: List[dict] = []
    cmd = "foreach ($IF in Get-NetIPAddress) {$IF.IPAddress"
    cmd += "+'|'+ $IF.InterfaceIndex +'|'+ $IF.PrefixLength"
    cmd += "+'|'+ $IF.PrefixOrigin +'|'+ $IF.SuffixOrigin"
    cmd += "+'|'+ $IF.AddressState}"
    keys = ["IPAddress", "InterfaceIndex", "PrefixLength",
            "PrefixOrigin", "SuffixOrigin", "AddressState"]
    for net in pshell(cmd).strip().splitlines():
        ip_list.append(dict(zip(keys, net.split('|'))))
    return ip_list


def _get_groups() -> list:
    groups: List[dict] = []
    out = pshell(
        'foreach($LG in Get-LocalGroup){$LG.Name'
        '+"|"+ $LG.Description}')
    for line in out.strip().splitlines():
        group: Dict[str, Any] = dict(
            zip(['Name', 'Description'], line.split("|")))
        out = pshell(
            f'foreach($M in Get-LocalGroupMember -Name \'{group["Name"]}'
            '\'){$M.ObjectClass +"|"+ $M.Name}')
        members = []
        for elem in out.strip().splitlines():
            members.append(
                dict(zip(['ObjectClass', 'Name'], elem.split("|"))))
        group['Members'] = members
        groups.append(group)
    return groups


def _get_users() -> List[dict]:
    users: List[dict] = []
    out = pshell(
        'foreach($U in Get-LocalUser){$U.Name +"|"+ $U.Enabled'
        '+"|"+ $U.Description}')
    for line in out.strip().splitlines():
        user = dict(
            zip(['Name', 'Enabled', 'Description'], line.split("|")))
        if user['Name'][-1] == "$":
            continue
        users.append(user)
    return users


def _get_folder(path: str) -> List[dict]:
    cmd = f'Get-Acl "{path}"'
    cmd += '|Select-Object -Property Owner -ExpandProperty Access'
    cmd += '|Out-String -width 2048'
    folder: Dict[str, Any] = dict(folder=path)
    folder['access'] = []
    for line in map(str.strip, pshell(cmd).splitlines()):
        if not line:
            continue
        key, val = map(str.strip, line.split(' : '))
        if key == 'Owner':
            folder['owner'] = val
            acl = dict()
        elif key == 'FileSystemRights':
            if val.strip('-').isnumeric():
                val = fsr.get(val, val)
            acl[key] = val
        else:
            acl[key] = val
        if key == 'PropagationFlags':
            folder['access'].append(acl)
    return folder


def _get_folders() -> List[dict]:
    folders: List[dict] = []
    cmd = 'Get-WmiObject Win32_LogicalDisk -Filter DriveType=3'
    cmd += '|Format-Table -Property DeviceID -HideTableHeaders'
    for drive in pshell(cmd).split():
        for element in os.scandir(drive+'\\'):
            if element.is_file() or element.is_symlink():
                continue
            if element.name[0] in '.$':
                continue
            folders.append(_get_folder(element.path))


def computer_stats() -> dict:
    return dict(objectSid=_get_sid(),
                ip_list=_get_ip_list(),
                localGroups=_get_groups(),
                localUsers=_get_users(),
                localFolders=_get_folders())


def _shutdown_server() -> dict:
    logger.info(
        'Received command to shutdown the computer.')
    try:
        out = run_cmd(('shutdown', '-s', '-f', '-t', '0'))
        return {'error': 0, 'output': out}
    except CalledProcessError as ex:
        logger.error(
            'Failed to shutdown the computer.')
        return {'error': 1,
                'output': ex.stdout}


def _disable_user(user: str) -> dict:
    logger.info(
        'Received command to disable user: %s', user)
    output = ''
    # logout user
    try:
        out = run_cmd(('quser', user))
        uid = out.strip().splitlines()[1].split()[2]
        output = run_cmd(('logoff', uid))
    except (TypeError, IndexError):
        logger.warning(
            'Failed to log off user: %s', user)
    except CalledProcessError as ex:
        logger.warning(
            'Failed to log off user: %s', user)
        output = ex.stdout
    # disable user
    try:
        output += run_cmd(('net', 'user', user, '/active:no'))
        return {'error': 0, 'output': output}
    except CalledProcessError as ex:
        logger.error('Failed to disable user: %s', user)
        output += ex.stdout
        return {'error': 1, 'output': output}


def _block_ip(address: str) -> dict:
    logger.info('Received command to block ip: %s', address)
    output = ''
    try:
        output += block_ip(address, 'in')
        output += block_ip(address, 'out')
        return {'error': 0, 'output': output}
    except CalledProcessError as ex:
        logger.error('Failed to block ip: %s', address)
        output += ex.stdout
        return {'error': 1, 'output': output}


def _isolete_host() -> dict:
    logger.info('Received command to isolate the computer.')
    output = ''
    try:
        out = run_cmd(('netsh', 'interface', 'show', 'interface'))
        interfaces = out.strip().splitlines()[2:]
        failed = False
        for line in interfaces:
            try:
                interface = line.split(maxsplit=3)[3]
                output += disable_interface(interface)
            except (CalledProcessError, TimeoutExpired) as ex:
                failed = True
                if hasattr(ex, 'stdout'):
                    output += ex.stdout
                logger.error(
                    'Failed to disable interface: %s', interface)
        if failed:
            return {'error': 1, 'output': output}
        return {'error': 0, 'output': output}
    except CalledProcessError as ex:
        logger.error('Failed to isolate the computer.')
        return {'error': 1, 'output': ex.stdout}


def _restart_server() -> dict:
    logger.info('Received command to restart the computer.')
    try:
        out = run_cmd(('shutdown', '-r', '-f', '-t', '0'))
        return {'error': 0, 'output': out}
    except CalledProcessError as ex:
        logger.error('Failed to restart the computer.')
        return {'error': 1, 'output': ex.stdout}


def _kill_process(pid: str) -> dict:
    logger.info('Received command to kill process: %s', pid)
    try:
        out = run_cmd(('taskkill', '/F', '/T', '/IM', pid))
        return {'error': 0, 'output': out}
    except CalledProcessError as ex:
        logger.error('Failed to kill process: %s', pid)
        return {'error': 1, 'output': ex.stdout}


def _uninstall_program(program: str) -> dict:
    logger.info('Received command to uninstall program: %s', program)
    cond = "description='{}'".format(program)
    try:
        out = run_cmd(('wmic', 'product', 'where', cond, 'uninstall'))
        return {'error': 0, 'output': out}
    except CalledProcessError as ex:
        logger.error('Failed to uninstall program: %s', program)
        return {'error': 1, 'output': ex.stdout}


def _run_cmd(cmd: str) -> dict:
    logger.info('Received command to run custom command: %s', cmd)
    try:
        out = run_cmd(cmd, shell=True)
        return {'error': 0, 'output': out}
    except CalledProcessError as ex:
        output = ex.stdout
    except FileNotFoundError as ex:
        output = str(ex)
    logger.error('Failed to run custom command: %s', cmd)
    return {'error': 1, 'output': output}


def _run_job(cmd, params: str) -> dict:
    if cmd == Command.SHUTDOWN_SERVER:
        res = _shutdown_server()
    elif cmd == Command.DISABLE_USER:
        res = _disable_user(params)
    elif cmd == Command.BLOCK_IP:
        res = _block_ip(params)
    elif cmd == Command.ISOLATE_HOST:
        res = _isolete_host()
    elif cmd == Command.RESTART_SERVER:
        res = _restart_server()
    elif cmd == Command.KILL_PROCESS:
        res = _kill_process(params)
    elif cmd == Command.UNINSTALL_PROGRAM:
        res = _uninstall_program(params)
    elif cmd == Command.RUN_CMD:
        res = _run_cmd(params)
    else:
        logger.error(
            'Received unknown command: %s (params: %s)', cmd, params)
        return {'error': 1, 'output': f'Received unknown command: {cmd}'}
    return res


def _check_winlogs_limit() -> None:
    min_size = 209715200
    try:
        out = run_cmd(('wevtutil', 'gl', 'Application'))
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('maxSize:'):
                logsize = int(line.split(':')[-1].strip())
                if logsize < min_size:
                    logger.warning(
                        'Windows log size is smaller than %s Bytes.', min_size)
                    cfg.set_winlog_small(True)
                else:
                    cfg.set_winlog_small(False)
                return
    except (CalledProcessError, FileNotFoundError):
        pass
    logger.error('Failed to check Windows logs limit')


def _check_ps_version() -> None:
    cmd = '$host.version'
    cmd += '|Format-Table -Property Major -HideTableHeaders'
    try:
        cfg.set_ps_old(int(pshell(cmd).strip() or 0) < 5)
    except (CalledProcessError, FileNotFoundError):
        cfg.set_ps_old(True)


def main():
    AgentClient().run()


if __name__ == '__main__':
    main()
