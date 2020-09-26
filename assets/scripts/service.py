# -*- coding: utf-8 -*-
from threading import Thread, Event
from time import sleep
from typing import List, Dict, Any, Optional
from subprocess import CalledProcessError, TimeoutExpired
from zipfile import ZipFile
import io
import json
import logging
import logging.handlers
import os
import subprocess
import socket
import sys
import time
if sys.platform != "linux":
    import winreg

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, 'libs'))
from flask import Flask, render_template, request
from utm_stack import ConfigMan, Command, ServiceStatus, __version__, APP_NAME
import requests


def _init_logger() -> logging.Logger:
    logdir = r'C:\ProgramData\UTMStack\logs'
    if sys.platform == 'linux':
        logdir = os.path.dirname(cfg.app_dir)

    if not os.path.exists(logdir):
        os.makedirs(logdir)

    logger = logging.Logger('UTMS')
    logger.parent = None  # type: ignore
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s')

    chandler = logging.StreamHandler()
    chandler.setLevel(logging.DEBUG)
    chandler.setFormatter(formatter)
    logger.addHandler(chandler)

    log_path = os.path.join(logdir, 'service.log')
    fhandler = logging.handlers.RotatingFileHandler(
        log_path, backupCount=5, maxBytes=2000000)
    fhandler.setLevel(logging.INFO)
    fhandler.setFormatter(formatter)
    logger.addHandler(fhandler)
    logger.log_path = log_path

    return logger


cfg = ConfigMan()
shutdown = Event()
logger = _init_logger()
server = Flask(__name__)
server.config['SEND_FILE_MAX_AGE_DEFAULT'] = 1  # disable caching


# ======== Server API =============

@server.errorhandler(Exception)
def handle_exception(e) -> None:
    logger.exception(e)


@server.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


@server.route('/', methods=['GET', 'POST'])
def index() -> str:
    fb_modules = get_filebeat_modules()
    mb_modules = get_metricbeat_modules()
    ctx = {
        'ip': cfg.get_ip(),
        'fb_inputs': cfg.get_filebeat_inputs(),
        'fb_dir': os.path.join(cfg.app_dir, 'Filebeat'),
        'fb_modules': fb_modules,
        'mb_modules': mb_modules,
        'status': ServiceStatus,
        'services': get_status(),
        'winlog_small': cfg.get_winlog_small(),
        'ps_old': cfg.get_ps_old(),
        'agent_logs': get_app_log(),
        'app_name': APP_NAME,
        'acl_enabled': cfg.get_acl_check(),
        'app_version': __version__,
    }
    return render_template('index.html', **ctx)


@server.route('/update_settings', methods=['POST'])
def update_settings() -> str:
    ip = request.form['ip']
    cfg.set_ip(ip)
    logger.info(f'Server IP updated to: {ip}')
    update_winlogbeat(ip)
    update_filebeat(ip)
    update_metricbeat(ip)
    cfg.set_pcs_time(0)
    cfg.set_swl_time(0)
    cfg.set_acls_time(0)
    cfg.set_agent_id(None)  # Force to register agent again
    return "OK"


@server.route('/filebeat_toggle_module', methods=['POST'])
def filebeat_toggle_module() -> str:
    mdir: str = os.path.join(cfg.filebeat_dir, 'modules.d')
    path: str = os.path.join(mdir, request.form['module'] + '.yml')
    if os.path.exists(path):
        action = 'Disabled'
        new_path = path + '.disabled'
    else:
        action = 'Enabled'
        new_path = path
        path += '.disabled'
    os.rename(path, new_path)
    logger.info('Filebeat module: %s %s', action, request.form['module'])

    modules: list = get_filebeat_modules()
    has_mod = True in [s for m, s in modules]
    if not has_mod and not cfg.get_filebeat_inputs():
        if nssm('stop', 'filebeat') is None:
            logger.error('Failed to stop Filebeat service.')
        else:
            logger.info('Filebeat service stopped.')
    else:
        if nssm('restart', 'filebeat') is None:
            logger.error('Failed to restart Filebeat service.')
        else:
            logger.info('Filebeat service restarted.')

    ctx = {'fb_modules': modules}
    return render_template('fbmodules_tab.html', **ctx)


@server.route('/metricbeat_toggle_module', methods=['POST'])
def metricbeat_toggle_module() -> str:
    mdir: str = os.path.join(cfg.metricbeat_dir, 'modules.d')
    path: str = os.path.join(mdir, request.form['module'] + '.yml')
    if os.path.exists(path):
        action = 'Disabled'
        new_path = path + '.disabled'
    else:
        action = 'Enabled'
        new_path = path
        path += '.disabled'
    os.rename(path, new_path)
    logger.info('Metricbeat module: %s %s', action, request.form['module'])

    modules: list = get_metricbeat_modules()
    has_mod = True in [s for m, s in modules]
    if not has_mod:
        if nssm('stop', 'metricbeat') is None:
            logger.error('Failed to stop Metricbeat service.')
        else:
            logger.info('Metricbeat service stopped.')
    else:
        if nssm('restart', 'metricbeat') is None:
            logger.error('Failed to restart Metricbeat service.')
        else:
            logger.info('Metricbeat service restarted.')

    ctx = {'mb_modules': modules}
    return render_template('mbmodules_tab.html', **ctx)


@server.route('/filebeat_add_input', methods=['POST'])
def filebeat_add_input() -> str:
    path: str = request.form['path']
    field: str = request.form['field']
    added = cfg.add_filebeat_input(path, field)
    if added:
        logger.info(
            'Added Filebeat input (%s, %s)',
            path, field)
        update_filebeat(cfg.get_ip())
        error = 0
    else:
        logger.warning(
            'Can not add add Filebeat input (%s, %s), path already used.',
            path, field)
        error = 1

    ctx = {'fb_inputs': cfg.get_filebeat_inputs(),
           'fbinputs_error': error}
    fbinputs_tab = render_template(
        'fbinputs_tab.html', **ctx)
    return fbinputs_tab


@server.route('/filebeat_del_input', methods=['POST'])
def filebeat_del_input() -> str:
    path: str = request.form['path']
    cfg.del_filebeat_input(path)
    logger.info('Deleted Filebeat input: %s', path)
    update_filebeat(cfg.get_ip())

    ctx = {'fb_inputs': cfg.get_filebeat_inputs()}
    return render_template(
        'fbinputs_tab.html', **ctx)


@server.route('/get_stats', methods=['POST'])
def _get_stats() -> str:
    ctx = {'status': ServiceStatus,
           'services': get_status(),
           'agent_logs': get_app_log()}
    return render_template('stats.html', **ctx)


@server.route('/acl_toggle', methods=['POST'])
def acl_toggle() -> str:
    acl_enabled = not cfg.get_acl_check()
    if acl_enabled:
        cfg.set_acls_time(0)
    cfg.set_acl_check(acl_enabled)
    logger.info('ACL module %s', 'enabled' if acl_enabled else 'disabled')

    ctx = dict(ip=cfg.get_ip(), acl_enabled=acl_enabled)
    return render_template('probe_tab.html', **ctx)


@server.route('/install_antivirus', methods=['POST'])
def install_antivirus() -> str:
    lkey: str = 'GUILIC=' + request.form['licensekey']
    installer = os.path.join(cfg.app_dir, 'wsasme.msi')
    logger.info('Installing antivirus')
    try:
        try:
            _run_cmd(('msiexec', '/uninstall', installer, '/qn'))
        except CalledProcessError:
            pass
        _run_cmd(('msiexec', '/i', installer, lkey,
                  'CMDLINE=SME,quiet', '/qn'))
        logger.info('Antivirus installed')
    except CalledProcessError as ex:
        logger.error('Failed to install antivirus: %s', ex.stdout)

    return 'Ok'

# =================================


def _run_cmd(cmd: tuple, **kwargs) -> str:
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.STDOUT
    kwargs['text'] = True
    kwargs['check'] = True
    return subprocess.run(cmd, **kwargs).stdout


def _ps(cmd: str) -> str:
    return _run_cmd(('powershell', '-NoProfile', '-Command', cmd))


def nssm(cmd: str, name: str) -> Optional[str]:
    if sys.platform == "linux":
        return None
    nssm_bin = os.path.join(cfg.app_dir, 'nssm.exe')
    if cmd == 'restart':
        subprocess.run(
            (nssm_bin, 'stop', name))
        sleep(1)
        try:
            out = subprocess.check_output(
                (nssm_bin, 'start', name), text=True)
            out = out.replace('\x00', '').strip()
        except CalledProcessError:
            out = None
    else:
        try:
            out = subprocess.check_output(
                (nssm_bin, cmd, name), text=True)
            out = out.replace('\x00', '').strip()
        except CalledProcessError:
            out = None
    return out


def get_status() -> dict:
    def status(text: Optional[str]) -> ServiceStatus:
        if text is None:
            return int(ServiceStatus.UNINSTALLED)
        if text == 'SERVICE_RUNNING':
            return int(ServiceStatus.RUNNING)
        else:
            return int(ServiceStatus.STOPPED)

    stats = dict()
    stats['filebeat'] = status(
        nssm('status', 'filebeat'))
    stats['metricbeat'] = status(
        nssm('status', 'metricbeat'))
    stats['winlogbeat'] = status(
        nssm('status', 'winlogbeat'))
    stats['hids'] = status(
        nssm('status', 'OssecSvc'))

    return stats


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
            lines = _ps(
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
    computer_data["objectSid"] = _ps(cmd).strip()

    # NETWORK
    ip_list: List[dict] = []
    cmd = "foreach ($IF in Get-NetIPAddress) {$IF.IPAddress"
    cmd += "+'|'+ $IF.InterfaceIndex +'|'+ $IF.PrefixLength"
    cmd += "+'|'+ $IF.PrefixOrigin +'|'+ $IF.SuffixOrigin"
    cmd += "+'|'+ $IF.AddressState}"
    keys = ["IPAddress", "InterfaceIndex", "PrefixLength",
            "PrefixOrigin", "SuffixOrigin", "AddressState"]
    for net in _ps(cmd).strip().splitlines():
        ip_list.append(dict(zip(keys, net.split('|'))))
    computer_data["ip_list"] = ip_list

    # GROUPS
    groups: List[dict] = []
    out = _ps(
        'foreach($LG in Get-LocalGroup){$LG.Name'
        '+"|"+ $LG.Description}')
    for g in out.strip().splitlines():
        group: Dict[str, Any] = dict(
            zip(['Name', 'Description'], g.split("|")))
        out = _ps(
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
    out = _ps(
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
    for drive in _ps(cmd).split():
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
            for line in map(str.strip, _ps(cmd).splitlines()):
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
                        f'Windows log size is smaller than {min_size}Bytes.')
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
        cfg.set_ps_old(int(_ps(cmd).strip() or 0) < 5)
    except (CalledProcessError, FileNotFoundError):
        cfg.set_ps_old(True)


def get_app_log() -> str:
    with open(logger.log_path) as fd:
        return '\n'.join(fd.read().split('\n')[-50:])


def _get_modules(name) -> list:
    modules = []
    modules_dir = os.path.join(cfg.app_dir, name, 'modules.d')
    for p in os.listdir(modules_dir):
        p = p.split('.')
        modules.append((p[0], p[-1] != 'disabled'))
    modules.sort(key=lambda e: e[0])
    return modules


def get_filebeat_modules() -> list:
    return _get_modules('Filebeat')


def get_metricbeat_modules() -> list:
    return _get_modules('Metricbeat')


def update_winlogbeat(ip: str) -> None:
    cfg_path = os.path.join(cfg.winlogbeat_dir, 'winlogbeat.yml')
    data = render_template('winlogbeat.yml', ip=ip)

    with open(cfg_path, 'w') as fd:
        fd.write(data)
    logger.info('Winlogbeat configuration updated.')

    if nssm('restart', 'winlogbeat') is None:
        logger.error('Failed to restart Winlogbeat service.')
    else:
        logger.info('Winlogbeat service restarted.')


def update_filebeat(ip: str) -> None:
    inputs = cfg.get_filebeat_inputs()
    cfg_path = os.path.join(cfg.filebeat_dir, 'filebeat.yml')
    data = render_template('filebeat.yml', ip=ip, inputs=inputs)

    with open(cfg_path, 'w') as fd:
        fd.write(data)
    logger.info('Filebeat configuration updated.')

    has_mod = True in [s for m, s in get_filebeat_modules()]
    if not inputs and not has_mod:
        if nssm('stop', 'filebeat') is None:
            logger.error('Failed to stop Filebeat service.')
        else:
            logger.info('Filebeat service stopped.')
    else:
        if nssm('restart', 'filebeat') is None:
            logger.error('Failed to restart Filebeat service.')
        else:
            logger.info('Filebeat service restarted.')


def update_metricbeat(ip: str) -> None:
    cfg_path = os.path.join(cfg.metricbeat_dir, 'metricbeat.yml')
    data = render_template('metricbeat.yml', ip=ip)

    with open(cfg_path, 'w') as fd:
        fd.write(data)
    logger.info('Metricbeat configuration updated.')

    has_mod = True in [s for m, s in get_metricbeat_modules()]
    if not has_mod:
        if nssm('stop', 'metricbeat') is None:
            logger.error('Failed to stop Metricbeat service.')
        else:
            logger.info('Metricbeat service stopped.')
    else:
        if nssm('restart', 'metricbeat') is None:
            logger.error('Failed to restart Metricbeat service.')
        else:
            logger.info('Metricbeat service restarted.')


def update_wazuh(ip: str, key: str) -> None:
    if sys.platform == "linux":
        cfg.hids_dir = os.path.dirname(cfg.app_dir)
    cfg_path = os.path.join(cfg.hids_dir, 'ossec.conf')

    with open(cfg_path, 'w') as fd:
        t = os.path.join(ROOT, 'templates', 'wazuh.conf')
        with open(t) as f:
            data = f.read().replace('{{WAZUH_IP}}', ip)
        fd.write(data)

    key_path = os.path.join(cfg.hids_dir, 'client.keys')
    with open(key_path, 'w') as fd:
        fd.write(key)

    logger.info('HIDS configuration updated.')

    if nssm('restart', 'OssecSvc') is None:
        logger.error('Failed to restart HIDS service.')
    else:
        logger.info('HIDS service restarted.')


def run_server(port: int) -> None:
    server.run(host='127.0.0.1', port=port, threaded=True)


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
            else:
                resp = r.json()
                if resp['error'] == 2:  # Agent not registered
                    cfg.set_agent_id(None)
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
                out = _run_cmd(('shutdown', '-s', '-f', '-t', '0'))
                return {'error': 0, 'output': out}
            except CalledProcessError as ex:
                logger.error(
                    'Failed to shutdown the computer.')
                return {'error': 1,
                        'output': ex.stdout}

        elif cmd == Command.DISABLE_USER:
            logger.info(
                f'Received command to disable user: {params}')
            output = ''
            # logout user
            try:
                out = _run_cmd(('quser', params))
                uid = out.strip().splitlines()[1].split()[2]
                output = _run_cmd(('logoff', uid))
            except (TypeError, IndexError):
                logger.warning(
                    f'Failed to log off user: {params}')
            except CalledProcessError as ex:
                logger.warning(
                    f'Failed to log off user: {params}')
                output = ex.stdout
            # disable user
            try:
                output += _run_cmd(
                    ('net', 'user', params, '/active:no'))
                return {'error': 0, 'output': output}
            except CalledProcessError as ex:
                logger.error(
                    f'Failed to disable user: {params}')
                output += ex.stdout
                return {'error': 1,
                        'output': output}

        elif cmd == Command.BLOCK_IP:
            logger.info(
                f'Received command to block ip: {params}')
            def block_ip(ip, direction):
                cmd = ('netsh', 'advfirewall', 'firewall',
                       'add', 'rule', f'name="UTMS_Block_{ip}"',
                       f'dir={direction}', 'interface=any',
                       'action=block', f'remoteip={ip}')
                return _run_cmd(cmd)

            output = ''
            try:
                output += block_ip(params, 'in')
                output += block_ip(params, 'out')
                return {'error': 0, 'output': output}
            except CalledProcessError as ex:
                logger.error(
                    f'Failed to block ip: {params}')
                output += ex.stdout
                return {'error': 1,
                        'output': output}

        elif cmd == Command.ISOLATE_HOST:
            logger.info(
                'Received command to isolate the computer.')
            def disable_interface(interface):
                cmd = ('netsh', 'interface', 'set', 'interface',
                       interface, 'admin=disable')
                return _run_cmd(cmd, timeout=30)

            output = ''
            try:
                out = _run_cmd(
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
                            f'Failed to disable interface: {interface}')
                if failed:
                    return {'error': 1, 'output': output}
                else:
                    return {'error': 0, 'output': output}
            except CalledProcessError as ex:
                logger.error(
                    'Failed to isolate the computer.')
                return {'error': 1,
                        'output': ex.stdout}

        elif cmd == Command.RESTART_SERVER:
            logger.info(
                'Received command to restart the computer.')
            try:
                out = _run_cmd(('shutdown', '-r', '-f', '-t', '0'))
                return {'error': 0, 'output': out}
            except CalledProcessError as ex:
                logger.error(
                    'Failed to restart the computer.')
                return {'error': 1,
                        'output': ex.stdout}

        elif cmd == Command.KILL_PROCESS:
            logger.info(
                f'Received command to kill process: {params}')
            try:
                out = _run_cmd(
                    ('taskkill', '/F', '/T', '/IM', params))
                return {'error': 0, 'output': out}
            except CalledProcessError as ex:
                logger.error(
                    f'Failed to kill process: {params}')
                return {'error': 1,
                        'output': ex.stdout}

        elif cmd == Command.UNINSTALL_PROGRAM:
            logger.info(
                f'Received command to uninstall program: {params}')
            q = "description='{}'".format(params)
            try:
                out = _run_cmd(
                    ('wmic', 'product', 'where', q, 'uninstall'))
                return {'error': 0, 'output': out}
            except CalledProcessError as ex:
                logger.error(
                    f'Failed to uninstall program: {params}')
                return {'error': 1,
                        'output': ex.stdout}

        elif cmd == Command.RUN_CMD:
            logger.info(
                f'Received command to run custom command: {params}')
            try:
                out = _run_cmd(params, shell=True)
                return {'error': 0, 'output': out}
            except CalledProcessError as ex:
                output = ex.stdout
            except FileNotFoundError as ex:
                output = str(ex)
            logger.error(
                f'Failed to run custom command: {params}')
            return {'error': 1, 'output': output}
        else:
            msg = f'Received unknown command: {cmd} (params: {params})'
            logger.error(msg)
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
                            f'Failed to get tasks from probe server ({self.ip})')
            except Exception as ex:
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
                            f' ({self.ip}), registering now.')
                        try:
                            self.register_agent()
                            logger.info(
                                'Agent registered on probe server:'
                                f' {self.ip}')
                        except (ConnectionError,
                                requests.ConnectionError,
                                requests.HTTPError):
                            self.agent_id = None
                            logger.exception(
                                'Failed to register Agent on probe'
                                f' server: {self.ip}')
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
                                'Failed to send computer status'
                                f' to server {self.ip}: {ex.stdout}')
                        except (ConnectionError,
                                requests.ConnectionError,
                                requests.HTTPError) as ex:
                            logger.exception(
                                'Failed to send computer status'
                                f' to server {self.ip}')

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
                                'Failed to send software list'
                                f' to server {self.ip}: {ex.stdout}')
                        except (ConnectionError,
                                requests.ConnectionError,
                                requests.HTTPError):
                            logger.exception(
                                'Failed to send software list'
                                f' to server: {self.ip}')

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
                                'Failed to send ACLs stats'
                                f' to server {self.ip}: {ex.stdout}')
                        except (ConnectionError,
                                requests.ConnectionError,
                                requests.HTTPError):
                            logger.exception(
                                'Failed to send ACLs stats'
                                f' to server: {self.ip}')

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
                            'Failed to send agent status to probe'
                            f' server: {self.ip}')
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
        t = Thread(target=run_server, args=(cfg.get_localport(),), daemon=True)
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


if __name__ == '__main__':
    AgentClient().run()
