# -*- coding: utf-8 -*-
import io
import json
import logging
import os
import socket
import subprocess
import time
import winreg
from subprocess import CalledProcessError, TimeoutExpired
from threading import Event, Thread
from typing import Any, Dict, List
from zipfile import ZipFile

import requests

from . import __version__
from .api import get_status, run_api, update_wazuh
from .utils import Command, ConfigMan, get_logger, ps, run_cmd

cfg = ConfigMan()
shutdown = Event()
logger = get_logger('service')


class AgentClient:
    def __init__(self):
        self.jobs_delay = 15
        self.stats_delay = 60*4
        self.srv_port = cfg.get_probeport()
        self.agent_id = None
        self.ip = None

    def api_call(self, req: str, **kwargs):
        url = 'http://{}:{}/{}'.format(
            self.ip, self.srv_port, req)
        kwargs['agent_id'] = self.agent_id
        raw = kwargs.pop('raw', False)
        with requests.post(url, kwargs) as r:
            r.raise_for_status()
            if raw:
                return r.content
            resp = r.json()
            if resp['error'] == 2:  # Agent not registered
                cfg.set_agent_id('')
            return resp

    def register_agent(self) -> None:
        self.agent_id = socket.gethostname()
        resp = self.api_call('register_agent')
        wazuh_key, self.agent_id = resp['key'], resp['agent_id']
        cfg.set_wazuh_key(wazuh_key)
        cfg.set_agent_id(self.agent_id)
        update_wazuh(self.ip, wazuh_key)

    def check_for_updates(self) -> None:
        data = self.api_call(
            'get_update', agent_version=__version__, raw=True)
        cfg.set_last_check_for_updates(time.time())
        if data:
            with io.BytesIO(data) as fd:
                with ZipFile(fd) as zfile:
                    zfile.extractall(cfg.app_dir)
            shutdown.set()

    def run_job(self, cmd, params) -> dict:
        if cmd == Command.SHUTDOWN_SERVER:
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

        elif cmd == Command.DISABLE_USER:
            logger.info(
                'Received command to disable user: %s', params)
            output = ''
            # logout user
            try:
                out = run_cmd(('quser', params))
                uid = out.strip().splitlines()[1].split()[2]
                output = run_cmd(('logoff', uid))
            except (TypeError, IndexError):
                logger.warning(
                    'Failed to log off user: %s', params)
            except CalledProcessError as ex:
                logger.warning(
                    'Failed to log off user: %s', params)
                output = ex.stdout
            # disable user
            try:
                output += run_cmd(
                    ('net', 'user', params, '/active:no'))
                return {'error': 0, 'output': output}
            except CalledProcessError as ex:
                logger.error(
                    'Failed to disable user: %s', params)
                output += ex.stdout
                return {'error': 1,
                        'output': output}

        elif cmd == Command.BLOCK_IP:
            logger.info(
                'Received command to block ip: %s', params)
            output = ''
            try:
                output += block_ip(params, 'in')
                output += block_ip(params, 'out')
                return {'error': 0, 'output': output}
            except CalledProcessError as ex:
                logger.error(
                    'Failed to block ip: %s', params)
                output += ex.stdout
                return {'error': 1,
                        'output': output}

        elif cmd == Command.ISOLATE_HOST:
            logger.info(
                'Received command to isolate the computer.')
            output = ''
            try:
                out = run_cmd(
                    ('netsh', 'interface', 'show', 'interface'))
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
                return {'error': 1,
                        'output': ex.stdout}

        elif cmd == Command.RESTART_SERVER:
            logger.info('Received command to restart the computer.')
            try:
                out = run_cmd(('shutdown', '-r', '-f', '-t', '0'))
                return {'error': 0, 'output': out}
            except CalledProcessError as ex:
                logger.error(
                    'Failed to restart the computer.')
                return {'error': 1,
                        'output': ex.stdout}

        elif cmd == Command.KILL_PROCESS:
            logger.info(
                'Received command to kill process: %s', params)
            try:
                out = run_cmd(
                    ('taskkill', '/F', '/T', '/IM', params))
                return {'error': 0, 'output': out}
            except CalledProcessError as ex:
                logger.error(
                    'Failed to kill process: %s', params)
                return {'error': 1,
                        'output': ex.stdout}

        elif cmd == Command.UNINSTALL_PROGRAM:
            logger.info(
                'Received command to uninstall program: %s', params)
            q = "description='{}'".format(params)
            try:
                out = run_cmd(
                    ('wmic', 'product', 'where', q, 'uninstall'))
                return {'error': 0, 'output': out}
            except CalledProcessError as ex:
                logger.error(
                    'Failed to uninstall program: %s', params)
                return {'error': 1,
                        'output': ex.stdout}

        elif cmd == Command.RUN_CMD:
            logger.info(
                'Received command to run custom command: %s', params)
            try:
                out = run_cmd(params, shell=True)
                return {'error': 0, 'output': out}
            except CalledProcessError as ex:
                output = ex.stdout
            except FileNotFoundError as ex:
                output = str(ex)
            logger.error(
                'Failed to run custom command: %s', params)
            return {'error': 1, 'output': output}
        else:
            logger.error(
                'Received unknown command: %s (params: %s)', cmd, params)
            msg = f'Received unknown command: {cmd}'
            return {'error': 1, 'output': msg}

    def start_jobs_worker(self) -> None:
        while not shutdown.is_set():
            try:
                if self.ip and cfg.get_agent_id():
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

                    logger.info('Requesting tasks to probe server.')
                    try:
                        jobs = self.api_call('get_jobs')['jobs']
                        cfg.add_jobs(jobs)
                        jobs = cfg.get_jobs()
                        for job_id, cmd_id, params in jobs:
                            cfg.remove_job(job_id)
                            res = self.run_job(cmd_id, params)
                            data = {'job_id': job_id,
                                    'result': json.dumps(res)}
                            self.api_call(
                                'set_job_result', **data)
                        if not jobs:
                            logger.info('There are not new tasks.')
                    except (ConnectionError,
                            requests.ConnectionError,
                            requests.HTTPError):
                        logger.info(
                            'Failed to get tasks from probe server (%s)',
                            self.ip)
            except Exception:
                logger.exception(
                    'Unexpected error on the tasks thread')
            shutdown.wait(self.jobs_delay)

    def start_stats_worker(self) -> None:
        while not shutdown.is_set():
            check_winlogs_limit()
            check_ps_version()
            try:
                self.ip = cfg.get_ip()
                if self.ip:
                    self.agent_id = cfg.get_agent_id()
                    if not self.agent_id:
                        logging.info(
                            'Agent is not registered on probe server'
                            ' (%s), registering now.', self.ip)
                        try:
                            self.register_agent()
                            logger.info(
                                'Agent registered on probe server: %s',
                                self.ip)
                        except (ConnectionError,
                                requests.ConnectionError,
                                requests.HTTPError):
                            self.agent_id = None
                            logger.exception(
                                'Failed to register Agent on probe server: %s',
                                self.ip)
                            shutdown.wait(10)
                            continue

                    last_sent = cfg.get_pcs_time()
                    time_elapsed = (time.time() - last_sent)/3600
                    if time_elapsed >= 24:
                        try:
                            logger.info(
                                'Sending computer status to server.')
                            self.api_call(
                                'computer_status',
                                status=json.dumps(computer_stats()))
                            cfg.set_pcs_time(time.time())
                        except CalledProcessError as ex:
                            logger.exception(
                                'Failed to send computer status to server'
                                ' %s: %s', self.ip, ex.stdout)
                        except (ConnectionError,
                                requests.ConnectionError,
                                requests.HTTPError):
                            logger.exception(
                                'Failed to send computer status to server %s',
                                self.ip)

                    last_sent = cfg.get_swl_time()
                    time_elapsed = (time.time() - last_sent)/3600
                    if time_elapsed >= 24:
                        try:
                            logger.info(
                                'Sending software list to server.')
                            self.api_call(
                                'software_status',
                                status=json.dumps(
                                    list_installed_software()))
                            cfg.set_swl_time(time.time())
                        except CalledProcessError as ex:
                            logger.exception(
                                'Failed to send software list to server'
                                ' %s: %s', self.ip, ex.stdout)
                        except (ConnectionError,
                                requests.ConnectionError,
                                requests.HTTPError):
                            logger.exception(
                                'Failed to send software list to server: %s',
                                self.ip)

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
                                self.ip, ex.stdout)
                        except (ConnectionError,
                                requests.ConnectionError,
                                requests.HTTPError):
                            logger.exception(
                                'Failed to send ACLs stats to server: %s',
                                self.ip)

                    data = get_status()
                    data['agent_version'] = __version__
                    logger.info(
                        'Sending agent status to probe server.')
                    try:
                        self.api_call(
                            'update_status', **data)
                    except (ConnectionError,
                            requests.ConnectionError,
                            requests.HTTPError):
                        logger.exception(
                            'Failed to send agent status to probe server: %s',
                            self.ip)
                else:
                    logger.warning(
                        'Probe server IP not configured.')
            except Exception:
                logger.exception(
                    'Unexpected error on the status thread')
            if cfg.get_agent_id():
                shutdown.wait(self.stats_delay)
            else:
                shutdown.wait(10)

    def run(self) -> None:
        # Start Flask server
        logger.info('Starting GUI server.')
        t = Thread(target=run_api, daemon=True)
        t.start()

        # Check for jobs
        logger.info('Starting tasks thread.')
        t = Thread(target=self.start_jobs_worker, daemon=True)
        t.start()

        # Send status
        logger.info('Starting status thread.')
        t = Thread(target=self.start_stats_worker, daemon=True)
        t.start()

        shutdown.wait()


def block_ip(ip, direction):
    cmd = ('netsh', 'advfirewall', 'firewall',
           'add', 'rule', f'name="UTMS_Block_{ip}"',
           f'dir={direction}', 'interface=any',
           'action=block', f'remoteip={ip}')
    return run_cmd(cmd)


def disable_interface(interface):
    cmd = ('netsh', 'interface', 'set', 'interface',
           interface, 'admin=disable')
    return run_cmd(cmd, timeout=30)


def list_installed_software() -> list:
    def _get_soft(hive, flag) -> list:
        aReg = winreg.ConnectRegistry(None, hive)
        try:
            rpath = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            aKey = winreg.OpenKey(
                aReg, rpath, 0, winreg.KEY_READ | flag)
        except FileNotFoundError:
            return []

        software_list = []

        count_subkey = winreg.QueryInfoKey(aKey)[0]

        for i in range(count_subkey):
            software = {}
            try:
                asubkey_name = winreg.EnumKey(aKey, i)
                asubkey = winreg.OpenKey(aKey, asubkey_name)
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
    for u in users:
        try:
            lines = ps(
                cmd % (u['sAMAccountName'],)).strip().splitlines()
            user = {}
            user["objectSid"] = str(u["objectSid"])
            aclGroup = []
            acl = {}
            for line in map(str.strip, lines):
                if not line:
                    continue
                key, val = map(str.strip, line.split(' : '))
                if key in keys:
                    acl[key] = val
                elif key == 'PropagationFlags':
                    acl[key] = val
                    aclGroup.append(acl)
                    acl = {}
            user["userACLs"] = aclGroup
            acls.append(user)
        except:
            logger.warning(
                'Failed to get ACL info for user %s',
                u['sAMAccountName'])
            continue
    return acls


def computer_stats() -> dict:
    computer_data: Dict[str, Any] = dict()

    # HOST
    host_name = socket.gethostname()
    cmd = '$ID = (new-object System.Security.Principal.NTAccount("'
    cmd += host_name + '$"))\n'
    t = '[System.Security.Principal.SecurityIdentifier]'
    cmd += f'return $ID.Translate( {t} ).toString()'
    computer_data["objectSid"] = ps(cmd).strip()

    # NETWORK
    ip_list: List[dict] = []
    cmd = "foreach ($IF in Get-NetIPAddress) {$IF.IPAddress"
    cmd += "+'|'+ $IF.InterfaceIndex +'|'+ $IF.PrefixLength"
    cmd += "+'|'+ $IF.PrefixOrigin +'|'+ $IF.SuffixOrigin"
    cmd += "+'|'+ $IF.AddressState}"
    keys = ["IPAddress", "InterfaceIndex", "PrefixLength",
            "PrefixOrigin", "SuffixOrigin", "AddressState"]
    for net in ps(cmd).strip().splitlines():
        ip_list.append(dict(zip(keys, net.split('|'))))
    computer_data["ip_list"] = ip_list

    # GROUPS
    groups: List[dict] = []
    out = ps(
        'foreach($LG in Get-LocalGroup){$LG.Name'
        '+"|"+ $LG.Description}')
    for g in out.strip().splitlines():
        group: Dict[str, Any] = dict(
            zip(['Name', 'Description'], g.split("|")))
        out = ps(
            f'foreach($M in Get-LocalGroupMember -Name \'{group["Name"]}'
            '\'){$M.ObjectClass +"|"+ $M.Name}')
        members = []
        for m in out.strip().splitlines():
            members.append(
                dict(zip(['ObjectClass', 'Name'], m.split("|"))))
        group['Members'] = members
        groups.append(group)
    computer_data["localGroups"] = groups

    # USERS
    users: List[dict] = []
    out = ps(
        'foreach($U in Get-LocalUser){$U.Name +"|"+ $U.Enabled'
        '+"|"+ $U.Description}')
    for u in out.strip().splitlines():
        user = dict(
            zip(['Name', 'Enabled', 'Description'], u.split("|")))
        if user['Name'][-1] == "$":
            continue
        users.append(user)
    computer_data["localUsers"] = users

    # FOLDERS
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
    folders = []
    cmd = 'Get-WmiObject Win32_LogicalDisk -Filter DriveType=3'
    cmd += '|Format-Table -Property DeviceID -HideTableHeaders'
    for drive in ps(cmd).split():
        for f in os.scandir(drive+'\\'):
            if f.is_file() or f.is_symlink():
                continue
            if f.name[0] in '.$':
                continue
            cmd = f'Get-Acl "{f.path}"'
            cmd += '|Select-Object -Property Owner -ExpandProperty Access'
            cmd += '|Out-String -width 2048'
            folder: Dict[str, Any] = dict(folder=f.path)
            access: List[dict] = []
            for line in map(str.strip, ps(cmd).splitlines()):
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
                    access.append(acl)
            folder['access'] = access
            folders.append(folder)
    computer_data["localFolders"] = folders
    return computer_data


def check_winlogs_limit() -> None:
    min_size = 209715200
    try:
        out = subprocess.check_output(
            ('wevtutil', 'gl', 'Application'), text=True)
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


def check_ps_version() -> None:
    cmd = '$host.version'
    cmd += '|Format-Table -Property Major -HideTableHeaders'
    try:
        cfg.set_ps_old(int(ps(cmd).strip() or 0) < 5)
    except (CalledProcessError, FileNotFoundError):
        cfg.set_ps_old(True)


def main():
    AgentClient().run()


if __name__ == '__main__':
    main()
