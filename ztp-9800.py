# TODO: docstrings .. top and functions TODO: transfrom into a Class construct to make the code more extensible
#  beyond ZTP flow, where main() does not get called if used as import

# Cisco guestshell cli module
from cli import cli, clip, configure, configurep, execute, executep
# traditional python modules
import concurrent.futures
import configparser
import re
from collections import namedtuple
import time
import sys
import inspect
import logging
from typing import Union

# only turn this on if want more gory detail of big blocks of logging output and such
# code_debugging is for all points of debugging
code_debugging = False
# code_debugging_TODO is for only focused areas
code_debugging_TODO = False

IOSXEDEVICE_FILESYS_DEFAULT = 'flash:'


def main():

    try:
        # create a device so can start to call logger aspects
        configure_logger()

        # schedule a reload in case something goes wrong
        cli('enable ; reload in 60 reason IOSXEDevice.main@ primary watchdog')

        # calling it "self".. so it sort of looks and acts a lot like the Class behavior
        # this Class object does a large part of the effort as it figures out
        # most of the details of the device and fetches the needful support file
        self = IOSXEDevice()

        self.ztp_log.info('START')
        self.ztp_log.info('This device is model %s and serial %s' % (self.model, self.serial))

        # do some basic config for things like SSH/etc
        self.do_configure(self.basic_access_commands)

        self.version_tar_map = {
            'img': self.ztp_script._replace(filename='C9800-L-universalk9_wlc.17.09.04a.SPA.bin',
                                            md5='70d8a8c0009fc862349a200fd62a0244'),
        }

        if self.upgrade_required:
            # step across .. img, smu, apdp, apsp, web
            for component in self.version_tar_map:
                # step across each file.. and if it is a nested dict, step across the nesting
                for entry in self.version_tar_map[component]:
                    if not self.check_file_exists(filename=entry.filename):
                        self.ztp_log.info('attempting to transfer filename to device')
                        transferit = entry
                        # only for develop cycling
                        if code_debugging: self.do_cli('reload in 30 reason main@ file_transfer %s' % [transferit])
                        self.file_transfer(transferit)
                    elif not self.verify_dst_image_md5(filename=entry.filename, src_md5=entry.md5):
                        self.ztp_log.info('FailedXfer filename does not exist')
                        raise ValueError('FailedXfer')

                    # TODO: look for INSTALL vs BUNDLE mode from software_map table and flip if/where needed
                    self.deploy_eem_upgrade_script(app_label='upgrade', filename=self.entry.filename)
                    self.ztp_log.info('performing the upgrade - switch will reload')

                    # only for develop cycling
                    if code_debugging: self.do_cli('reload in 90 reason main@ event manager run upgrade')
                    self.do_cli('event manager run upgrade')
                    timeout_pause = 3600
                    self.ztp_log.info(
                        'pausing %s seconds to let eem script upgrade trigger a reload' % timeout_pause)
                    time.sleep(timeout_pause)
                    self.ztp_log.info(
                        'eem upgrade took more than %s seconds to reload the device. increase the sleep time by few '
                        'minutes before retrying' % timeout_pause)

            # Only do remove_inactive .. if actually did an upgrade in case someone is doing these steps manually and
            # want to keep inactive around
            self.deploy_eem_remove_inactive_script(app_label='remove_inactive')
            self.do_cli('event manager run remove_inactive')
            timeout_pause = 30
            self.ztp_log.info('pausing %s seconds for any config changes to settle in' % timeout_pause)
            time.sleep(timeout_pause)

        else:
            self.ztp_log.info('no upgrade is required')

        # TODO: add SMU and APSP & APDP support

        self.check_and_change_chassis(chassis_cur=self.chassis_cur, chassis_tar=self.chassis_tar)

        self.ztp_log.info('Day0 configuration push')
        self.configure_merge(filename=self.device_config_file.filename)
        timeout_pause = 30
        self.ztp_log.info('pausing %s seconds for any config changes to settle in' % timeout_pause)
        time.sleep(timeout_pause)
        # TODO:  .. neutered for now
        self.do_cli('! write memory')

        # regenerate the local rsa key for ssh/etc
        self.do_configure('crypto key generate rsa modulus 4096')

        # stage the cleanup routine so can SSH to the DHCP address assigned
        self.do_configure(self.basic_access_commands_cleanup)

        # whew.... finally done :) :)
        self.ztp_log.info('THE END')

    except Exception as e:
        ztp_log = get_logger()
        ztp_log.critical('aborting. failure encountered during day 0 provisioning. error details below')
        ztp_log.debug('an error occurred: %s' % type(e).__name__)
        print(e)
        # TODO: experimenting
        self.ztp_log.debug('inspect.stack() is %s' % inspect.stack())
        self.ztp_log.debug('inspect.trace() is %s' % inspect.trace())

        cli('enable ; show logging | inc ZTP')
        sys.exit(1)


def configure_logger(logger_name='ZTP'):
    logging.getLogger(logger_name)
    ztp_log = get_logger(logger_name)
    if code_debugging or code_debugging_TODO:
        ztp_log.setLevel(logging.DEBUG)
    else:
        ztp_log.setLevel(logging.INFO)

    # Create sys.stdout Stream handler
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter('%(asctime)s: %(levelname)s: %(funcName)s@%(lineno)d: %(message)s'))
    ztp_log.addHandler(handler)

    ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
    ztp_log.info('logger %s created' % ztp_log)

    def eem_action_syslog(record: logging.LogRecord = None):
        # trigger a SYSLOG to the IOS-XE logger
        if record:
            # SYSLOG emergency/0, alert/1, critical/2, error/3, warning/4, notice/5, info/6, debug/7
            pri = '5'
            if record.levelname == 'DEBUG': pri = '7'
            if record.levelname == 'INFO': pri = '6'
            if record.levelname == 'WARNING': pri = '4'
            if record.levelname == 'ERROR': pri = '3'
            if record.levelname == 'CRITICAL': pri = '2'

            # transform single/double quotes to tilde ~ eem_commands to avoid delimiter collisions
            # TODO: see if escape or literal syntax works for double and single quotes
            new_msg = record.msg
            new_msg = new_msg.replace('"', '~')
            new_msg = new_msg.replace("'", "~")
            new_msg = new_msg.splitlines()

            eem_commands = ['no event manager applet eem_action_syslog',
                            'event manager applet eem_action_syslog',
                            'event none maxrun 600', ]
            i = 100
            for line in new_msg:
                i = i + 1
                # break new_msg into chunks
                chunks, chunk_size = len(line), 100
                line_chunks = [line[i:i + chunk_size] for i in range(0, chunks, chunk_size)]
                for nibble in line_chunks:
                    nibble_msg = '%s@%s: %s' % (record.funcName, record.lineno, nibble)
                    eem_commands.append('action %03d syslog priority %s msg \"%s\" facility %s' % (i, pri, nibble_msg, 'ZTP'))
            # do not call do_configure().. call configure() directly .. otherwise will get loop
            configure(eem_commands)
            # do not call do_cli().. call cli() directly .. otherwise will get loop
            cli('enable ; event manager run eem_action_syslog')
            eem_commands = ['no event manager applet eem_action_syslog']
            # do not call do_configure().. call configure() directly .. otherwise will get loop
            configure(eem_commands)
        # always return True to allow the logger to send message to other handlers
        return True

    # trigger a SYSLOG message as well using addFilter technique
    ztp_log.addFilter(eem_action_syslog)
    if code_debugging or code_debugging_TODO:
        configure('logging trap debugging')
        ztp_log.info('configured logging trap debugging')

    # TODO .. see if this can be fixed
    '''
    # create a new filename > 5 mb size
    handler = logging.handlers.RotatingFileHandler(filename='flash/guest-share/ztp.log',
                                                   mode='a', maxBytes=5 * 1024 * 1024,
                                                   backupCount=10, encoding=None, delay=0)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter('%(asctime)s: %(levelname)s: %(funcName)s@%(lineno)d: %(message)s'))
    ztp_log.addHandler(handler)
    '''
    return ztp_log


def get_logger(logger_name='ZTP'):
    ztp_log = logging.getLogger(logger_name)
    ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
    return ztp_log

TransferInfo_tuple = namedtuple(
    typename='TransferInfo_tuple',
    field_names='section version_target xfer_mode username password hostname port path filename md5',
)
TransferInfo_tuple_defaults = {
    'section': None,
    'version_target': None,
    'xfer_mode': None, 'username': None, 'password': None, 'hostname': None,
    'port': None, 'path': None, 'filename': None, 'md5': None,
}
chassis_tuple = namedtuple(typename='chassis', field_names='chassis_num chassis_pri')

def TransferInfo_tuple_create(**kwargs):
    transferit = TransferInfo_tuple(**TransferInfo_tuple_defaults)
    transferit = transferit._replace(**kwargs)
    return transferit


class IOSXEDevice(dict):
    '''
    IOSXEDevice as currently running guestshell
    '''

    def __init__(self):
        '''
        create device attributes by extracting off of device
        '''
        super().__init__()

        self.ztp_log = get_logger()
        # configure_logger() MUST come before all of these, as these all have embedded ztp_log calls
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))

        # get script_name so can know some starting point server to fetch initial defaults
        self.ztp_script = self.get_ztp_script()
        # only after get_ztp_script .. logging buffered clears the log.. and breaks finding the "PNP" log message
        if code_debugging or code_debugging_TODO: configure('logging buffered 200000000')

        self.ztp_seed_defaults_file = None
        self.ztp_seed_defaults_contents = None

        if self.ztp_script:
            transferit = self.ztp_script._replace(filename='ztp-seed-defaults.ini')
            self.ztp_seed_defaults_file = self.file_transfer(transferit)
            self.ztp_seed_defaults_contents = self.do_cli('more %s%s' %
                                                          (IOSXEDEVICE_FILESYS_DEFAULT, transferit.filename))
        self.xfer_servers = None
        self.basic_access_commands = None
        self.software_map = None
        self.basic_access_commands_cleanup = None

        ini_file_contents = self.ztp_seed_defaults_contents
        if ini_file_contents:

            structure = 'xfer_server'
            results = self.extract_ini_structure(ini_file_contents=ini_file_contents, structure=structure)
            if results: self.xfer_servers = results

            # now that servers are loaded.. activate the syslog and ntp references
            self.configure_syslog_and_ntp(self.xfer_servers)

            structure = 'basic_access_commands'
            key = 'commands'
            results = self.extract_ini_section_key(ini_file_contents=ini_file_contents, section=structure, key=key)
            if results: self.basic_access_commands = results

            structure='basic_access_commands_cleanup'
            key='commands'
            results = self.extract_ini_section_key(ini_file_contents=ini_file_contents, section=structure, key=key)
            if results: self.basic_access_commands_cleanup = results

            structure = 'software_map'
            results = self.extract_ini_structure(ini_file_contents=ini_file_contents, structure=structure)
            if results: self.software_map = results

        self.show_version = self.get_show_version()
        self.model = self.get_model(self.show_version)
        self.serial = self.get_serial(self.show_version)
        self.version_cur = self.get_version_cur(self.show_version)
        self.version_cur_mode = self.get_version_cur_mode(self.show_version)

        self.device_seed_file = None
        self.device_seed_file_contents = None

        if self.ztp_script and self.serial and self.model:
            transferit = self.ztp_script._replace(filename='ztp-seed-%s-%s.ini' % (self.model, self.serial))
            self.device_seed_file = self.file_transfer(transferit)
            self.device_seed_file_contents = self.do_cli('more %s%s' %
                                                          (IOSXEDEVICE_FILESYS_DEFAULT, transferit.filename))
        ini_file_contents = self.device_seed_file_contents
        if ini_file_contents:

            # revisit these .. override if device specific if exist

            structure = 'xfer_server'
            results = self.extract_ini_structure(ini_file_contents=ini_file_contents, structure=structure)
            if results: self.xfer_servers = results

            # activate the syslog and ntp references .. add any device specific servers
            self.configure_syslog_and_ntp(self.xfer_servers)

            structure = 'basic_access_commands'
            key = 'commands'
            results = self.extract_ini_section_key(ini_file_contents=ini_file_contents, section=structure, key=key)
            if results: self.basic_access_commands = results

            structure='basic_access_commands_cleanup'
            key='commands'
            results = self.extract_ini_section_key(ini_file_contents=ini_file_contents, section=structure, key=key)
            if results: self.basic_access_commands_cleanup = results

            structure='software_map'
            results = self.extract_ini_structure(ini_file_contents=ini_file_contents, structure=structure)
            if results: self.software_map = results

        self.device_config_file = None
        self.device_config_file_contents = None

        if self.ztp_script and self.serial and self.model:
            # TODO: fetch more specific file if called out in ztp-seed-MODEL-SERIAL.ini
            transferit = self.ztp_script._replace(filename='%s-%s.cfg' % (self.model, self.serial))
            self.device_config_file = self.file_transfer(transferit)
            self.device_config_file_contents = self.do_cli('more %s%s' %
                                                          (IOSXEDEVICE_FILESYS_DEFAULT, transferit.filename))

        self.chassis_cur = self.get_chassis_cur()
        self.chassis_tar = self.extract_chassis_tar(config_file_contents=self.device_config_file_contents)

        # TODO: version_tar_map
        self.version_tar_map = None
        self.version_tar = self.get_version_tar()
        # load this with the respective part of the software_table from the software_map
        self.version_tar_map = {
            'img': TransferInfo_tuple_create(filename='C9800-L-universalk9_wlc.17.09.04a.SPA.bin',
                                             md5='70d8a8c0009fc862349a200fd62a0244'),
        }

        self.upgrade_required = self.check_upgrade_required(self.version_cur, self.version_tar)

    def get_ztp_script(self):
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        ztp_script = TransferInfo_tuple_create()
        show_log = self.do_cli('show logging | inc PNP-6-PNP_SCRIPT_STARTED')
        if code_debugging: self.ztp_log.debug('show_log is %s' % show_log)
        try:
            '''
            %PNP-6-PNP_SCRIPT_STARTED: Script (http://192.168.201.68/ztp/ztp-9800.py)
            '''
            results = re.search(pattern=r'%PNP-6-PNP_SCRIPT_STARTED:\s+Script\s+\((\S+)://(\S+)/(\S+)/(\S+)\)',
                                string=show_log)
            if results:
                ztp_script = ztp_script._replace(xfer_mode=results.group(1),
                                                 hostname=results.group(2),
                                                 path=results.group(3),
                                                 filename=results.group(4))
                self.ztp_log.info('found ztp_script %s' % [ztp_script])
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        # not really sending back list, but putting list wrapper to let it do %s
        self.ztp_log.debug('returning %s' % [ztp_script])
        return ztp_script

    def get_show_version(self):
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        self.ztp_log.info('CLI show version')
        show_version = self.do_cli('show version')
        if code_debugging: self.ztp_log.debug('found show_version \n%s' % show_version)
        self.ztp_log.debug('returning \n%s' % show_version)
        return show_version

    def get_model(self, show_version: str = None):
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        model = None
        if show_version:
            try:
                model = re.search(pattern="Model Number\s+:\s+(\S+)", string=show_version).group(1)
            except AttributeError:
                model = re.search(pattern="cisco\s(\w+-.*?)\s", string=show_version).group(1)
            self.ztp_log.info('found model %s' % model)
        self.ztp_log.debug('returning %s' % model)
        return model

    def get_serial(self, show_version: str = None):
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        serial = None
        if show_version:
            try:
                serial = re.search(pattern="System Serial Number\s+:\s+(\S+)", string=show_version).group(1)
            except AttributeError:
                serial = re.search(pattern="Processor board ID\s+(\S+)", string=show_version).group(1)
            self.ztp_log.info('found serial %s' % serial)
        self.ztp_log.debug('returning %s' % serial)
        return serial

    def get_version_cur(self, show_version: str = None):
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        version_cur = None
        if show_version:
            try:
                results = re.search(r"Cisco IOS XE Software, Version\s+(\S+)", show_version)
                if results:
                    version_cur = results.group(1)
                    self.ztp_log.info('found %s' % version_cur)
            except Exception as e:
                self.ztp_log.debug('error occurred: %s' % type(e).__name__)
                print(e)
        self.ztp_log.debug('returning %s' % version_cur)
        return version_cur

    def get_version_cur_mode(self, show_version: str = None):
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        version_cur_mode = None
        if show_version:
            try:
                results = re.search(pattern="Installation mode is\s+(\S+)", string=show_version)
                if results:
                    version_cur_mode = results.group(1)
                    self.ztp_log.info('found %s' % version_cur_mode)
            except Exception as e:
                self.ztp_log.debug('error occurred: %s' % type(e).__name__)
                print(e)
        self.ztp_log.debug('returning %s' % version_cur_mode)
        return version_cur_mode

    def get_device_seed_filename(self, serial: str = None, model: str = None,
                                 script: TransferInfo_tuple = TransferInfo_tuple_create()):
        self.ztp_log.debug('called from %s()@%s with (model=%s, script=%s)' %
                           (inspect.stack()[1][3], inspect.stack()[1][2], model, script))
        transferit = TransferInfo_tuple_create()
        if script and serial and model:
            transferit = script
            transferit = transferit._replace(filename='ztp-seed-%s-%s.ini' % (model, serial))
        # not really sending back list, but putting list wrapper to let it do %s
        self.ztp_log.info('is %s' % [transferit])
        self.ztp_log.debug('returning %s' % [transferit])
        return transferit

    def get_device_config_filename(self, serial: str = None, model: str = None,
                                   script: TransferInfo_tuple = TransferInfo_tuple_create()):
        self.ztp_log.debug('called from %s()@%s with (serial=%s, script=%s)' %
                           (inspect.stack()[1][3], inspect.stack()[1][2], serial, script))
        transferit = TransferInfo_tuple_create()
        if script and serial and model:
            transferit = script
            transferit = transferit._replace(filename='%s-%s.cfg' % (model, serial))
        # TODO: extract a more preferred filename .. and transferit definition
        # not really sending back list, but putting list wrapper to let it do %s
        self.ztp_log.info('is %s' % [transferit])
        self.ztp_log.debug('returning %s' % [transferit])
        return transferit

    def get_chassis_cur(self):
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        show_chassis = self.do_cli('show chassis')
        chassis = None
        '''
        *1       Active   f4bd.9e56.fa80     1      V02     Ready                0.0.0.0        
        '''
        if True:
            try:
                results = re.search(r"\*(\d)\s+(\S+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\d)",
                                    show_chassis)
                if results:
                    chassis = chassis_tuple(chassis_num=results.group(1), chassis_pri=results.group(4))
                    self.ztp_log.info('found %s' % [chassis])
            except Exception as e:
                self.ztp_log.debug('error occurred: %s' % type(e).__name__)
                print(e)
        self.ztp_log.debug('returning s' % [chassis])
        return chassis

    def extract_chassis_tar(self, config_file_contents: str = None):
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        chassis = None
        if config_file_contents:
            try:
                # TODO: extract chassis_priority from desired config filename interpolation
                results = True
                if results:
                    chassis = chassis_tuple(chassis_num='2', chassis_pri='2')
                    self.ztp_log.info('found %s' % [chassis])
            except Exception as e:
                self.ztp_log.debug('error occurred: %s' % type(e).__name__)
                print(e)
        self.ztp_log.debug('returning %s' % [chassis])
        return chassis

    def check_and_change_chassis(self, chassis_cur: chassis_tuple = None, chassis_tar: chassis_tuple = None):
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        if chassis_cur and chassis_tar:
            do_reload = False
            if chassis_cur.chassis_pri != chassis_tar.chassis_pri:
                # changing priority should not trigger a reboot
                self.ztp_log.info('chassis priority needs to be changed from %s to %s' %
                                  (chassis_cur.chassis_pri, chassis_tar.chassis_pri))
                self.do_cli('chassis %s priority %s' %
                            (chassis_cur.chassis_num, chassis_tar.chassis_pri))
                do_reload = True
            elif chassis_cur.chassis_num != chassis_tar.chassis_num:
                # changing chassis number, should automatically trigger a reboot
                self.ztp_log.info('chassis number needs to be changed from %s to %s' %
                                  (chassis_cur.chassis_num, chassis_tar.chassis_num))
                self.do_cli('chassis %s renumber %s' %
                            (chassis_cur.chassis_num, chassis_tar.chassis_num))
                do_reload = True
            if do_reload:
                self.do_cli('reload in 1 reason check_and_change_chassis() do_reload')
                timeout_pause = 180
                self.ztp_log.info(
                    'pausing %s seconds to let check_and_change_chassis@ number from %s to %s trigger a reload' %
                    (timeout_pause, chassis_cur.chassis_num, chassis_tar.chassis_num))
                time.sleep(timeout_pause)
        # if did not do a change and reload, return True to indicate all is good
        self.ztp_log.debug('returning %s' % True)
        return True

    def get_version_tar(self):
        '''
        determine best software target from per serial config filename, overall software_map, else overall target
        :return:
        '''
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        # TODO process tables to yield serial, software, global pecking order
        version_tar = None
        self.ztp_log.info('is %s' % version_tar)
        self.ztp_log.debug('returning %s' % version_tar)
        return version_tar

    def configure_replace(self, filename: str = None, filesys: str = IOSXEDEVICE_FILESYS_DEFAULT):
        self.ztp_log.debug('called from %s()@%s with (filename=%s, filesys=%s)' % (
            inspect.stack()[1][3], inspect.stack()[1][2], filename, filesys))
        results = None
        if filename:
            self.do_cli('configure replace %s%s force' % (filesys, filename))
            # TODO: sdiff to check if changes took effect
        self.ztp_log.info('is %s' % results)
        self.ztp_log.debug('returning %s' % results)
        return results

    def configure_merge(self, filename: str = None, filesys: str = IOSXEDEVICE_FILESYS_DEFAULT):
        self.ztp_log.debug('called from %s()@%s with (filename=%s, filesys=%s)' % (
            inspect.stack()[1][3], inspect.stack()[1][2], filename, filesys))
        results = None
        if filename:
            self.do_cli('copy %s%s running-config' % (filesys, filename))
            # TODO: sdiff to check if changes took effect
        self.ztp_log.info('is %s' % results)
        self.ztp_log.debug('returning %s' % results)
        return results

    def check_file_exists(self, filename: str = None, filesys: str = IOSXEDEVICE_FILESYS_DEFAULT):
        self.ztp_log.debug('called from %s()@%s with (filename=%s, filesys=%s)' % (
            inspect.stack()[1][3], inspect.stack()[1][2], filename, filesys))
        dir_check = 'dir ' + filesys + filename
        results = self.do_cli(dir_check)
        if filename:
            if 'No such filename or directory' in results:
                self.ztp_log.warning('%s does NOT exist on %s' % (filename, filesys))
                results = False
            elif 'Directory of %s%s' % (filesys, filename) in results:
                self.ztp_log.info('%s does EXIST on %s' % (filename, filesys))
                results = True
            elif 'Directory of %s%s' % ('bootflash:/', filename) in results:
                self.ztp_log.info('%s does EXIST on %s' % (filename, 'bootflash:/'))
                results = True
            else:
                self.ztp_log.error('UnexpectedOutput')
                raise ValueError('UnexpectedOutput')
        self.ztp_log.info('returning %s' % results)
        return results

    def deploy_eem_upgrade_script(self, app_label='upgrade',
                                  filesys: str = IOSXEDEVICE_FILESYS_DEFAULT, filename: str = None):
        self.ztp_log.debug('called from %s()@%s with (filename=%s, app_label=%s)' %
                           (inspect.stack()[1][3], inspect.stack()[1][2], filename, app_label))
        if filename:
            install_command = 'install add filename ' + filesys + filename + ' activate commit'
            eem_commands = ['no event manager applet %s' % app_label,
                            'event manager applet % s' % app_label,
                            'event none maxrun 600',
                            'action 1.0 cli command "enable"',
                            'action 2.0 cli command "%s" pattern "\[y\/n\/q\]"' % install_command,
                            'action 2.1 cli command "n" pattern "proceed"',
                            'action 2.2 cli command "y"'
                            ]
            self.do_configure(eem_commands)

    def deploy_eem_remove_inactive_script(self, app_label='remove_inactive'):
        self.ztp_log.debug('called from %s()@%s with (app_label=%s)' %
                           (inspect.stack()[1][3], inspect.stack()[1][2], app_label))
        if True:
            install_command = 'install remove inactive'
            eem_commands = ['no event manager applet %s' % app_label,
                            'event manager applet %s' % app_label,
                            'event none maxrun 600',
                            'action 1.0 cli command "enable"',
                            'action 2.0 cli command "%s" pattern "\[y\/n\]"' % install_command,
                            'action 2.1 cli command "y" pattern "proceed"',
                            'action 2.2 cli command "y"'
                            ]
            self.do_configure(eem_commands)

    def file_transfer(self, transferit: TransferInfo_tuple = TransferInfo_tuple_create(),
                      filesys: str = IOSXEDEVICE_FILESYS_DEFAULT):
        self.ztp_log.debug('called from %s()@%s with (transferit=%s)' % (
            inspect.stack()[1][3], inspect.stack()[1][2], transferit))
        if transferit.xfer_mode and transferit.hostname and transferit.filename:

            # TODO: only take up to '://' or subset
            xfer_mode = transferit.xfer_mode + '://' if transferit.xfer_mode else ''
            username = transferit.username if transferit.username else ''
            password = ':' + transferit.password if transferit.username and transferit.password  else ''
            # TODO: remove any leading or trailing '/'
            hostname = '@' if transferit.username else ''
            hostname = hostname + transferit.hostname if transferit.hostname else ''
            port = ':' + transferit.port if transferit.port else ''
            # TODO: remove any leading or trailing '/'
            path = '/' + transferit.path if transferit.path else ''
            filename = '/' + transferit.filename if transferit.filename else ''

            command_delete = 'delete ' + filesys + filename
            command = ('copy ' + xfer_mode + username + password + hostname + port + path + filename +
                       ' ' + filesys + filename)
            command_set = command_delete + ' ; ' + command

            try:
                self.ztp_log.info('CLI %s' % command_set)
                self.do_cli('%s' % command_set)
            except Exception as e:
                self.ztp_log.debug('error occurred: %s' % type(e).__name__)
                print(e)
        # not really sending back list, but putting list wrapper to let it do %s
        self.ztp_log.debug('returning %s' % [transferit])
        return transferit

    def do_cli(self, command: str = None):
        self.ztp_log.debug('called from %s()@%s with (command=%s)' %
                           (inspect.stack()[1][3], inspect.stack()[1][2], command))
        results = None
        try:
            results = cli('enable ; %s' % command)
        except Exception as e:
            self.ztp_log.debug('An error occurred: %s' % type(e).__name__)
            self.ztp_log.debug('(command=%s) and got results \n%s' % (command, results))
            print(e)
            timeout_pause = 10
            self.ztp_log.info('Pause %s seconds .. and Retry %s' % (timeout_pause, command))
            time.sleep(timeout_pause)
            try:
                results = cli('enable ; %s' % command)
            except Exception as e:
                self.ztp_log.debug('error occurred: %s' % type(e).__name__)
                print(e)
                # only print results if got an exception
                self.ztp_log.debug('(command=%s) and got results \n%s' % (command, results))
        # don't log results... as most of the results are long
        return results

    def do_configure(self, command: Union[str, list]):
        self.ztp_log.debug('called from %s()@%s with (command=%s)' %
                           (inspect.stack()[1][3], inspect.stack()[1][2], command))
        results = None
        try:
            results = configure(command)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
            self.ztp_log.debug('(command=%s) and got results \n%s' % (command, results))
        # don't log results... as most of the results are long
        return results

    def check_upgrade_required(self, version_cur: str = None, version_tar: str = None):
        self.ztp_log.debug('called from %s()@%s with (version_cur=%s, version_tar=%s)' %
                          (inspect.stack()[1][3], inspect.stack()[1][2], version_cur, version_cur))
        results = None
        if version_cur and version_tar:
            self.ztp_log.info('Code Version Current is %s and Code Version Target is %s' % (version_cur, version_tar))
            results = version_cur == version_tar
            self.ztp_log.info('is %s' % results)
            self.ztp_log.debug('returning %s' % results)
        return results

    def verify_dst_image_md5(self, src_md5: str = None,
                             filesys: str = IOSXEDEVICE_FILESYS_DEFAULT, filename: str = None):
        self.ztp_log.debug('called from %s()@%s with (src_md5=%s, filesys=%s, filename=%s)' %
                          (inspect.stack()[1][3], inspect.stack()[1][2], src_md5, filesys, filename))
        results = None
        if filename and src_md5:
            dst_md5 = None
            try:
                verify_md5 = 'verify /md5 ' + filesys + filename
                self.ztp_log.info('CLI %s' % verify_md5)
                dst_md5 = self.do_cli(verify_md5)
                if src_md5 in dst_md5:
                    self.ztp_log.info('MD5 hashes match')
                    results = True
                else:
                    self.ztp_log.warning('MD5 hashes do NOT match')
                    results = False
            except Exception as e:
                self.ztp_log.error('MD5 checksum failed due to an exception')
                print(e)
                if code_debugging: self.ztp_log.debug('src_md5 is %s dst_md5 is %s' % (src_md5, dst_md5))
                results = False
        self.ztp_log.info('is %s' % results)
        self.ztp_log.debug('returning %s' % results)

    def extract_ini_section_key(self, ini_file_contents: str = None,
                                section: str = None, section_partial: bool = False,
                                key: str = None):
        """
        returns
            - if both section and key are specified, return section/key else None
            - if only section is specified and sec_partial is False return True if the section is found else False
            - if only section is specified and sec_partial is True return section names that are partial match else None

        :param ini_file_contents:
        :param section:
        :param section_partial:
        :param key:
        :return:
        """
        self.ztp_log.debug('called from %s()@%s with (section=%s, section_partial=%s, key=%s)' %
                           (inspect.stack()[1][3], inspect.stack()[1][2], section, section_partial, key))
        results = None
        if ini_file_contents:
            try:
                config = configparser.ConfigParser()
                config.sections()
                config.read_string(ini_file_contents)
                if section and key and section in config and key in config[section]:
                    results = config[section][key]
                    self.ztp_log.debug('found section=%s key=%s %s' % (section, key, results))
                elif section and key and section in config and key not in config[section]:
                    results = None
                    self.ztp_log.debug('found section=%s key=%s %s' % (section, key, results))
                elif section and not key and not section_partial:
                    results = config[section].keys()
                    self.ztp_log.debug('found section=%s %s' % (section, [results]))
                elif section and not key and section_partial:
                    # .. look for model with the longest starts with match in section
                    results = [i for i in config.sections() if i.startswith(section)]
                    self.ztp_log.debug('found section=%s %s' % (section, results))
            except configparser.MissingSectionHeaderError:
                results = None
            except Exception as e:
                self.ztp_log.debug('error occurred: %s' % type(e).__name__)
                print(e)
        self.ztp_log.debug('returning %s' % results)
        return results

    def extract_ini_structure(self, ini_file_contents: str = None, structure: str = None):
        self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        structure_results = None

        if ini_file_contents and structure:
            # TODO: extract from filename as structure list
            if code_debugging_TODO: self.ztp_log.debug('ini_file_contents are \n%s' % ini_file_contents)
            # find the sections that partially match structure at the start .. and sort them
            results = self.extract_ini_section_key(ini_file_contents=ini_file_contents,
                                                   section=structure, section_partial=True)
            if isinstance(results, str): results = [results]
            if isinstance(results, list): results.sort()
            if code_debugging_TODO: self.ztp_log.debug(
                'ini_file_contents found %s partial sections %s' % (structure, results))
            # results has the list of section names
            structure_results = None
            if results:
                structure_results = []
                for section in results:
                    transferit = TransferInfo_tuple_create(section=section)
                    keys = self.extract_ini_section_key(ini_file_contents=ini_file_contents, section=section)
                    # only fetch keys for desired tuple
                    keys = [item for item in keys if item in transferit._fields]
                    # see if this section has any of our desired values
                    for key in keys:
                        key_val = self.extract_ini_section_key(ini_file_contents=ini_file_contents,
                                                               section=section, key=key)
                        if key_val:
                            transferit = transferit._replace(**{key:key_val})
                            self.ztp_log.debug('found %s' % [transferit])
                    structure_results.append(transferit)
                    self.ztp_log.debug('for section %s the full structure_results were %s' % (section, structure_results))

        if code_debugging or code_debugging_TODO: self.ztp_log.debug('is %s' % structure_results)
        self.ztp_log.debug('returning %s' % structure_results)
        return structure_results

    def configure_syslog_and_ntp(self, xfer_servers: list = None):
        self.ztp_log.debug('called from %s()@%s with (xfer_servers=%s)' %
                          (inspect.stack()[1][3], inspect.stack()[1][2], xfer_servers))
        if xfer_servers:
            for srv in xfer_servers:
                # TODO split into a list for processing
                cmd = None
                if srv.xfer_mode == 'syslog':   cmd = 'logging host'
                if srv.xfer_mode == 'ntp':      cmd = 'ntp server'
                hostname_list = re.split('[\s,]+',srv.hostname)
                if cmd:
                    for i in hostname_list: self.do_configure('%s %s' % (cmd,i))
        self.ztp_log.debug('returning %s' % xfer_servers)
        return xfer_servers


if __name__ == "__main__":
    # schedule a reload in case something goes wrong
    cli('enable ; reload in 60 reason before calling main()')
    main()
