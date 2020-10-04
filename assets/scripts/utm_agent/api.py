# -*- coding: utf-8 -*-
import os
import subprocess
import sys
from subprocess import CalledProcessError
from typing import Optional
from time import sleep

from . import __version__, APP_NAME
from .utils import ConfigMan, ServiceStatus, get_logger, run_cmd

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(ROOT), 'libs'))
from flask import Flask, render_template, request


server = Flask(__name__)
server.config['SEND_FILE_MAX_AGE_DEFAULT'] = 1  # disable caching
logger = get_logger('api')
cfg = ConfigMan()


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
    cfg.set_agent_id('')  # Force to register agent again
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
            run_cmd(('msiexec', '/uninstall', installer, '/qn'))
        except CalledProcessError:
            pass
        run_cmd(('msiexec', '/i', installer, lkey,
                 'CMDLINE=SME,quiet', '/qn'))
        logger.info('Antivirus installed')
    except CalledProcessError as ex:
        logger.error('Failed to install antivirus: %s', ex.stdout)

    return 'Ok'

# =================================


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
    def status(text: Optional[str]) -> int:
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


def _get_modules(name) -> list:
    modules = []
    modules_dir = os.path.join(cfg.app_dir, name, 'modules.d')
    for p in os.listdir(modules_dir):
        t = p.split('.')
        modules.append((t[0], t[-1] != 'disabled'))
    modules.sort(key=lambda e: e[0])
    return modules


def get_filebeat_modules() -> list:
    return _get_modules('Filebeat')


def get_metricbeat_modules() -> list:
    return _get_modules('Metricbeat')


def get_app_log() -> str:
    with open(logger.log_path) as fd:  # type: ignore
        return '\n'.join(fd.read().split('\n')[-50:])


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


def main() -> None:
    server.run(host='127.0.0.1', port=cfg.get_localport(), threaded=True)
