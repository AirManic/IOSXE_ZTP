# TODO: docstrings .. top and functions

# traditional python modules
import os
from typing import Union
import copy
from collections import namedtuple
import concurrent.futures
import configparser
import re
import time
import sys
import inspect
import logging
import pprint

# determine if running under IOS-XE guestshell
is_guestshell = os.uname().nodename == 'guestshell'

# Cisco guestshell cli module
# only load cli library if running on IOS-XE guestshell.  This way we can do local development on stock OS of IDE.
if is_guestshell:
    from cli import cli, clip, configure, configurep, execute, executep
else:
    # if not running in guestshell create placeholder functions so we can exercise the code for development work
    def cli(command: str):
        return ''
    def clip(command):
        return ''
    def configure(configuration: Union[str, list]):
        return []
    def configurep(configuration: Union[str, list]):
        return []
    def execute(command: str):
        return ''
    def executep(command: str):
        return ''

# only turn this on if want more gory detail of big blocks of logging output and such
# code_debugging is for all points of debugging
code_debugging = False
# code_debugging_TODO is for only focused areas
code_debugging_TODO = False

IOSXEDEVICE_FILESYS_DEFAULT = 'flash:'

TransferInfo_tuple_field_names = 'section version_target xfer_mode username password hostname port path filename md5'

TransferInfo_tuple = namedtuple(
    typename='TransferInfo_tuple',
    field_names=TransferInfo_tuple_field_names,
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

def TransferInfo_tuple_inherit(transferit_parent: TransferInfo_tuple = None, transferit_child: TransferInfo_tuple = None):
    if transferit_parent and transferit_child:
        for field in TransferInfo_tuple_field_names.split(' '):
            if not transferit_child.__getattribute__(field) and transferit_parent.__getattribute__(field):
                transferit_child = transferit_child._replace(**{field:transferit_parent.__getattribute__(field)})
    return transferit_child

if not is_guestshell:
    # if not running under guestshell, simulate the data locally
    SIM_ZTP_SCRIPT = TransferInfo_tuple_create(xfer_mode='scp',
                                               hostname='10.0.0.301',
                                               path='ztp',
                                               filename='SIM-ztp-9800.py')
    SIM_MODEL = 'C9800-L-C-K9'
    SIM_SERIAL = 'XXX235100CW'
    SIM_VERSION_CUR = '17.13.01'
    SIM_VERSION_CUR_MODE = 'BUNDLE'
    SIM_DEVICE_CONFIG_FILENAME = '%s-%s.cfg' % (SIM_MODEL, SIM_SERIAL)

def main():

    try:
        # create a device so can start to call logger aspects
        ztp_log = configure_logger()

        # schedule a reload in case something goes wrong
        reload_time = 2 * 60
        command = 'enable ; reload in %s reason IOSXEDevice.main@ primary watchdog' % reload_time
        cli(command)
        ztp_log.info('called cli(%s)' % command)

        ztp_log.info('\n***\n********** ZTP IOSXEDevice() Object Build **********\n***')
        # calling it "self".. so it sort of looks and acts a lot like the Class behavior
        # this Class object does a large part of the effort as it figures out
        # most of the details of the device and fetches the needful support file
        self = IOSXEDevice()

        self.ztp_log.info('\n***\n********** ZTP START **********\n***')

        self.ztp_log.info('This device is model %s and serial %s' % (self.model, self.serial))

        # do some basic config for things like SSH/etc
        self.do_configure(self.basic_access_commands)
        self.ztp_log.info('\n***\n********** ZTP BASIC ACCESS CONFIGURED **********\n***')

        self.ztp_log.info('\n***\n********** ZTP CHECK UPGRADE_REQUIRED **********\n***')
        if self.upgrade_required:
            # TODO: add SMU and APSP & APDP support
            for component in 'IMG SMU APDP APSP WEB':
                self.ztp_log.info('\n***\n********** ZTP %s **********\n***\n' % code_phase)
                # step across each file.. and if it is a nested dict, step across the nesting
                for entry in self.version_tar_map[component]:
                    if not self.check_file_exists(filename=entry.filename):
                        self.ztp_log.info('attempting to transfer filename to device')
                        transferit = entry
                        # only for develop cycling
                        self.file_transfer(transferit)
                    elif not self.verify_dst_image_md5(filename=entry.filename, src_md5=entry.md5):
                        self.ztp_log.info('FailedXfer filename does not exist')
                        raise ValueError('FailedXfer')

                        # TODO: look for INSTALL vs BUNDLE mode from software_map table and flip if/where needed
                        self.deploy_eem_upgrade_script(app_label='upgrade', filename=self.entry.filename)
                        self.ztp_log.info('performing the upgrade - switch will reload')

                        # only for develop cycling
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


        self.check_and_change_chassis(chassis_cur=self.chassis_cur, chassis_tar=self.chassis_tar)

        self.ztp_log.info('\n***\n********** ZTP Day0 CONFIGURATION PUSH **********\n***')

        # stage the cleanup routine so can SSH to the DHCP address assigned
        self.do_configure(self.basic_access_commands_cleanup)
        self.ztp_log.info('\n***\n********** ZTP BASIC ACCESS CLEANUP CONFIGURED **********\n***')

        # TODO: remove any ZTP temporary "logging" and "ntp" .. to clean up and let the final config be prefferred

        if self.device_config_file:
            self.configure_merge(filename=self.device_config_file.filename)
            timeout_pause = 30
            self.ztp_log.info('pausing %s seconds for any config changes to settle in' % timeout_pause)
            time.sleep(timeout_pause)

        # TODO:  .. neutered for now .. move this into INI file of eem for basic_access_commands_cleanup
        self.do_cli('! write memory')

        # regenerate the local rsa key for ssh/etc
        self.do_configure('crypto key generate rsa modulus 4096')

        # whew.... finally done :) :)
        self.ztp_log.info('WHEW!! THE END!!')

    except Exception as e:
        ztp_log = get_logger()
        ztp_log.critical('aborting. failure encountered during day 0 provisioning. error details below')
        ztp_log.debug('an error occurred: %s' % type(e).__name__)
        print(e)
        # TODO: experimenting
        # self.ztp_log.debug('inspect.stack() is %s' % inspect.stack())
        # self.ztp_log.debug('inspect.trace() is %s' % inspect.trace())
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
                line_chunks = [line[c:c + chunk_size] for c in range(0, chunks, chunk_size)]
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
    ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
    return ztp_log

class IOSXEDevice(dict):
    '''
    IOSXEDevice as currently running guestshell
    '''

    def __init__(self):
        '''
        create device attributes by extracting off of device
        '''
        try:

            super().__init__()

            self.ztp_log = get_logger()
            # configure_logger() MUST come before all of these, as these all have embedded ztp_log calls
            self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))

            # get script_name so can know some starting point server to fetch initial defaults
            if is_guestshell:
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... get_ztp_script **********\n***')
                self.ztp_script = self.get_ztp_script()
            else:
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... SIM_ZTP_SCRIPT **********\n***')
                self.ztp_script = SIM_ZTP_SCRIPT
                self.ztp_log.info('found SIM_ZTP_SCRIPT %s' % [self.ztp_script])

            # only after get_ztp_script .. logging buffered clears the log.. and breaks finding the "PNP" log message
            if code_debugging or code_debugging_TODO: configure('logging buffered 200000000')

            self.ztp_seed_defaults_file = None
            self.ztp_seed_defaults_contents = None

            if self.ztp_script:
                transferit = self.ztp_script._replace(section='ztp_seed_defaults_file',
                                                      filename='ztp-seed-defaults.ini')
                if is_guestshell:
                    self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... ztp_seed_defaults **********\n***')
                    self.ztp_seed_defaults_file = self.file_transfer(transferit)
                    self.ztp_seed_defaults_contents = self.do_cli('more %s%s' %
                                                                  (IOSXEDEVICE_FILESYS_DEFAULT, transferit.filename))
                else:
                    # if not running under guestshell, simulate the data locally
                    self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... SIM_ZTP_SEED_DEFAULTS_CONTENTS **********\n***')
                    self.ztp_seed_defaults_file = transferit
                    with open(self.ztp_seed_defaults_file.filename, 'r') as file:
                        self.ztp_seed_defaults_contents = file.read()

            self.xfer_servers = None
            self.basic_access_commands = None
            self.software_map = None
            self.software_tree = None
            self.basic_access_commands_cleanup = None

            ini_file_contents = self.ztp_seed_defaults_contents

            if ini_file_contents:

                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... ztp_seed_defaults xfer_servers **********\n***')
                structure = 'xfer_server'
                results = self.extract_ini_structure(ini_file_contents=ini_file_contents, structure=structure)
                if results: self.xfer_servers = results

                # now that servers are loaded.. activate the syslog and ntp references
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... ztp_seed_defaults configure_syslog_and_ntp **********\n***')
                self.configure_syslog_and_ntp(self.xfer_servers)

                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... ztp_seed_defaults basic_access_commands **********\n***')
                structure = 'basic_access_commands'
                key = 'commands'
                results = self.extract_ini_section_key(ini_file_contents=ini_file_contents, section=structure, key=key)
                if results: self.basic_access_commands = results

                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... ztp_seed_defaults basic_access_commands_cleanup **********\n***')
                structure='basic_access_commands_cleanup'
                key='commands'
                results = self.extract_ini_section_key(ini_file_contents=ini_file_contents, section=structure, key=key)
                if results: self.basic_access_commands_cleanup = results

                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... ztp_seed_defaults software_map **********\n***')
                structure = 'software_map'
                results = self.extract_ini_structure(ini_file_contents=ini_file_contents, structure=structure)
                if results: self.software_map = results

                results = self.extract_software_tree(software_map=self.software_map, seed_transferit=self.ztp_script)
                if results: self.software_tree = results

            if is_guestshell:
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... get_show_version **********\n***')
                self.show_version = self.get_show_version()
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... get_model **********\n***')
                self.model = self.get_model(self.show_version)
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... get_serial **********\n***')
                self.serial = self.get_serial(self.show_version)
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... get_version_cur **********\n***')
                self.version_cur = self.get_version_cur(self.show_version)
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... get_version_cur_mode **********\n***')
                self.version_cur_mode = self.get_version_cur_mode(self.show_version)
            else:
                # if not running under guestshell, simulate the data locally
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... SIM_MODEL **********\n***')
                self.model = SIM_MODEL
                self.ztp_log.info('found SIM_MODEL %s' % SIM_MODEL)
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... SIM_SERIAL **********\n***')
                self.serial = SIM_SERIAL
                self.ztp_log.info('found SIM_SERIAL %s' % SIM_SERIAL)
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... SIM_VERSION_CUR **********\n***')
                self.version_cur = SIM_VERSION_CUR
                self.ztp_log.info('found SIM_VERSION_CUR %s' % SIM_VERSION_CUR)
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... SIM_VERSION_CUR_MODE **********\n***')
                self.version_cur_mode = SIM_VERSION_CUR_MODE
                self.ztp_log.info('found SIM_VERSION_CUR_MODE %s' % SIM_VERSION_CUR_MODE)

            self.device_xfer_servers = None
            self.device_basic_access_commands = None
            self.device_software_map = None
            self.device_software_tree = None
            self.device_basic_access_commands_cleanup = None

            self.device_seed_file = None
            self.device_seed_file_contents = None

            if self.ztp_script and self.serial and self.model:
                transferit = self.ztp_script._replace(section='device_seed_file',
                                                      filename='ztp-seed-%s-%s.ini' % (self.model, self.serial))
                if is_guestshell:
                    self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... device_seed_file_contents **********\n***')
                    self.device_seed_file = self.file_transfer(transferit)
                    self.device_seed_file_contents = self.do_cli('more %s%s' %
                                                                  (IOSXEDEVICE_FILESYS_DEFAULT, transferit.filename))
                else:
                    # if not running under guestshell, simulate the data locally
                    self.ztp_log.info(
                        '\n***\n********** ZTP IOSXEDevice() ... SIM_DEVICE_SEED_DEFAULTS_CONTENTS **********\n***')
                    self.device_seed_file = transferit
                    with open(self.device_seed_file.filename, 'r') as file:
                        self.device_seed_file_contents = file.read()

            ini_file_contents = self.device_seed_file_contents

            if ini_file_contents:

                # revisit these .. override if device specific if exist

                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... device_seed_file xfer_server **********\n***')
                structure = 'xfer_server'
                results = self.extract_ini_structure(ini_file_contents=ini_file_contents, structure=structure)
                if results: self.device_xfer_servers = results

                # activate the syslog and ntp references .. add any device specific servers
                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... device_seed_file configure_syslog_and_ntp **********\n***')
                self.configure_syslog_and_ntp(self.device_xfer_servers)

                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... device_seed_file device_basic_access_commands **********\n***')
                structure = 'basic_access_commands'
                key = 'commands'
                results = self.extract_ini_section_key(ini_file_contents=ini_file_contents, section=structure, key=key)
                if results: self.device_basic_access_commands = results

                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... device_seed_file device_basic_access_commands_cleanup **********\n***')
                structure='basic_access_commands_cleanup'
                key='commands'
                results = self.extract_ini_section_key(ini_file_contents=ini_file_contents, section=structure, key=key)
                if results: self.device_basic_access_commands_cleanup = results

                self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... device_seed_file device_software_map **********\n***')
                structure='software_map'
                results = self.extract_ini_structure(ini_file_contents=ini_file_contents, structure=structure)
                if results: self.device_software_map = results

                results = self.extract_software_tree(software_map=self.device_software_map, seed_transferit=self.ztp_script)
                if results: self.device_software_tree = results

            self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... device_config_file **********\n***')
            self.device_config_file = None
            self.device_config_file_contents = None

            if self.ztp_script and self.serial and self.model:
                transferit = self.ztp_script._replace(section='device_config_file',
                                                      filename='%s-%s.cfg' % (self.model, self.serial))
                if is_guestshell:
                    # TODO: fetch more specific file if called out in ztp-seed-MODEL-SERIAL.ini
                    self.device_config_file = self.file_transfer(transferit)
                    self.device_config_file_contents = self.do_cli('more %s%s' %
                                                                  (IOSXEDEVICE_FILESYS_DEFAULT, transferit.filename))
                    # TODO .. look for logging servers in the device_config_file_contents and activate those as well
                else:
                    self.ztp_log.info(
                        '\n***\n********** ZTP IOSXEDevice() ... SIM_DEVICE_CONFIG_FILE_CONTENTS **********\n***')
                    self.device_config_file = transferit
                    with open(self.device_config_file.filename, 'r') as file:
                        self.device_config_file_contents = file.read()

            self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... chassis_cur & chassis_tar **********\n***')
            self.chassis_cur = self.get_chassis_cur()
            self.chassis_tar = self.extract_chassis_tar(config_file_contents=self.device_config_file_contents)

            self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... version_tar **********\n***')
            # TODO: version_tar_map
            self.version_tar = self.get_version_tar()
            self.version_tar_map = None
            # load this with the respective part of the software_table from the software_map .. use self.device_software_map then self.software_map
            self.version_tar_map = {
                'img': TransferInfo_tuple_create(filename='C9800-L-universalk9_wlc.17.09.04a.SPA.bin',
                                                 md5='70d8a8c0009fc862349a200fd62a0244'),
            }

            self.ztp_log.info('\n***\n********** ZTP IOSXEDevice() ... upgrade_required **********\n***')
            self.upgrade_required = self.check_upgrade_required(self.version_cur, self.version_tar)

        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)

    def get_ztp_script(self):
        self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        try:
            self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
            ztp_script = TransferInfo_tuple_create(section='ztp_script')
            show_log = self.do_cli('show logging | inc PNP-6-PNP_SCRIPT_STARTED')
            if code_debugging: self.ztp_log.debug('show_log is %s' % show_log)
            results = re.search(pattern=r'%PNP-6-PNP_SCRIPT_STARTED:\s+Script\s+\((\S+)://(\S+)/(\S+)/(\S+)\)',
                                string=show_log)
            if results:
                ztp_script = ztp_script._replace(xfer_mode=results.group(1),
                                                 hostname=results.group(2),
                                                 path=results.group(3),
                                                 filename=results.group(4))
                self.ztp_log.info('found ztp_script %s' % [ztp_script])
            self.ztp_log.debug('returning %s' % [ztp_script])
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        # not really sending back list, but putting list wrapper to let it do %s
        return ztp_script

    def get_show_version(self):
        self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        try:
            self.ztp_log.debug('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
            show_version = self.do_cli('show version')
            if code_debugging: self.ztp_log.debug('found show_version \n%s' % show_version)
            self.ztp_log.debug('returning \n%s' % show_version)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        return show_version

    def get_model(self, show_version: str = None):
        try:
            self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
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
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)

    def get_serial(self, show_version: str = None):
        self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
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
        self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        version_cur = None
        if show_version:
            try:
                results = re.search(r"Cisco IOS XE Software, Version\s+(\S+)", show_version)
                if results:
                    version_cur = results.group(1)
                    self.ztp_log.info('found version_cur %s' % version_cur)
            except Exception as e:
                self.ztp_log.debug('error occurred: %s' % type(e).__name__)
                print(e)
        self.ztp_log.debug('returning %s' % version_cur)
        return version_cur

    def get_version_cur_mode(self, show_version: str = None):
        self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        version_cur_mode = None
        if show_version:
            try:
                results = re.search(pattern="Installation mode is\s+(\S+)", string=show_version)
                if results:
                    version_cur_mode = results.group(1)
                    self.ztp_log.info('found version_cur_mode %s' % version_cur_mode)
            except Exception as e:
                self.ztp_log.debug('error occurred: %s' % type(e).__name__)
                print(e)
        self.ztp_log.debug('returning %s' % version_cur_mode)
        return version_cur_mode

    def get_chassis_cur(self):
        self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))

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
        self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))

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
        try:
            self.ztp_log.info('called from %s@%s with (chassis_cur=%s, chassis_tar=%s' %
                              (inspect.stack()[1][3], inspect.stack()[1][2], chassis_cur, chassis_tar))
            results = None
            if chassis_cur and chassis_tar:
                do_reload = False
                if chassis_cur == chassis_tar:
                    results = True
                    do_reload = False
                if chassis_cur.chassis_pri != chassis_tar.chassis_pri:
                    # changing priority should not trigger a reboot
                    self.ztp_log.info('chassis priority needs to be changed from %s to %s' %
                                      (chassis_cur.chassis_pri, chassis_tar.chassis_pri))
                    self.do_cli('chassis %s priority %s' %
                                (chassis_cur.chassis_num, chassis_tar.chassis_pri))
                    do_reload = True
                if chassis_cur.chassis_num != chassis_tar.chassis_num:
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
            self.ztp_log.debug('returning %s' % results)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        return results

    def get_version_tar(self):
        try:
            self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
            # TODO process tables to yield serial, software, global pecking order
            version_tar = None
            self.ztp_log.info('is %s' % version_tar)
            self.ztp_log.debug('returning %s' % version_tar)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        return version_tar

    def configure_replace(self, filename: str = None, filesys: str = IOSXEDEVICE_FILESYS_DEFAULT):
        try:
            self.ztp_log.debug('called from %s()@%s with (filename=%s, filesys=%s)' % (
                inspect.stack()[1][3], inspect.stack()[1][2], filename, filesys))
            results = None
            if filename:
                cmd = 'configure replace %s%s force' % (filesys, filename)
                self.ztp_log.info('calling do_cli(%s)' % cmd)
                self.do_cli(cmd)
                # TODO: sdiff to check if changes took effect
                results = True
            self.ztp_log.debug('returning %s' % results)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        return results

    def configure_merge(self, filename: str = None, filesys: str = IOSXEDEVICE_FILESYS_DEFAULT):
        try:
            self.ztp_log.info('called from %s()@%s with (filename=%s, filesys=%s)' % (
                inspect.stack()[1][3], inspect.stack()[1][2], filename, filesys))
            results = None
            if filename:
                cmd = 'copy %s%s running-config' % (filesys, filename)
                self.ztp_log.info('calling do_cli(%s)' % cmd)
                self.do_cli(cmd)
                # TODO: sdiff to check if changes took effect
                results = True
            self.ztp_log.debug('returning %s' % results)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        return results

    def check_file_exists(self, filename: str = None, filesys: str = IOSXEDEVICE_FILESYS_DEFAULT):
        try:
            results = None
            self.ztp_log.info('called from %s()@%s with (filename=%s, filesys=%s)' % (
                inspect.stack()[1][3], inspect.stack()[1][2], filename, filesys))
            dir_check = 'dir ' + filesys + filename
            cli_results = self.do_cli(dir_check)
            if filename:
                if 'No such filename or directory' in cli_results:
                    self.ztp_log.warning('%s does NOT exist on %s' % (filename, filesys))
                    results = False
                elif 'Directory of %s%s' % (filesys, filename) in cli_results:
                    self.ztp_log.info('%s does EXIST on %s' % (filename, filesys))
                    results = True
            self.ztp_log.debug('returning %s' % results)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        return results

    def deploy_eem_upgrade_script(self, app_label='upgrade',
                                  filesys: str = IOSXEDEVICE_FILESYS_DEFAULT, filename: str = None):
        try:
            self.ztp_log.info('called from %s()@%s with (filename=%s, app_label=%s)' %
                               (inspect.stack()[1][3], inspect.stack()[1][2], filename, app_label))
            results = None
            if app_label and filename:
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
                results = True
            self.ztp_log.debug('returning %s' % results)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        return results
    def deploy_eem_remove_inactive_script(self, app_label='remove_inactive'):
        try:
            self.ztp_log.info('called from %s()@%s with (app_label=%s)' %
                               (inspect.stack()[1][3], inspect.stack()[1][2], app_label))
            results = None
            if app_label:
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
                results = True
            self.ztp_log.debug('returning %s' % results)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        return results

    def file_transfer(self, transferit: TransferInfo_tuple = None, filesys: str = IOSXEDEVICE_FILESYS_DEFAULT):
        try:
            self.ztp_log.info('called from %s()@%s with (transferit=%s)' % (
                inspect.stack()[1][3], inspect.stack()[1][2], transferit))
            return_me = None
            if transferit and transferit.xfer_mode and transferit.hostname and transferit.filename:

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
                command_copy = ('copy ' + xfer_mode + username + password + hostname + port + path + filename +
                           ' ' + filesys + filename)

                self.do_cli('%s' % command_delete)
                self.do_cli('%s' % command_copy)
                return_me = transferit
                self.ztp_log.debug('returning %s' % return_me)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        return return_me

    def do_cli(self, command: str = None):
        try:
            self.ztp_log.info('called from %s()@%s with (command=%s)' %
                               (inspect.stack()[1][3], inspect.stack()[1][2], command))
            return_me = None
            results = None
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
                self.ztp_log.debug('(command=%s) and got results \n%s' % (command, results))
                print(e)
            # don't log results... as most of the results are long
            return_me = results
        return results

    def do_configure(self, command: Union[str, list]):
        try:
            self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
            self.ztp_log.debug('called from %s()@%s with (command=%s)' %
                               (inspect.stack()[1][3], inspect.stack()[1][2], command))
            return_me = None
            results = None
            results = configure(command)
            self.ztp_log.debug('(command=%s) got \n\n%s' % (command, return_me))
            if results: return_me = results
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        return return_me

    def check_upgrade_required(self, version_cur: str = None, version_tar: str = None):
        try:
            self.ztp_log.info('called from %s@%s with (version_cur=%s, version_tar=%s)' %
                              (inspect.stack()[1][3], inspect.stack()[1][2], version_cur, version_tar))
            return_me = None
            if version_cur and version_tar:
                return_me = version_cur == version_tar
                self.ztp_log.info('is %s' % return_me)
            self.ztp_log.debug('returning %s' % return_me)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
            return_me = None
        return return_me

    def verify_dst_image_md5(self, src_md5: str = None,
                             filesys: str = IOSXEDEVICE_FILESYS_DEFAULT, filename: str = None):
        try:
            self.ztp_log.info('called from %s@%s with (src_md5=%s, filesys=%s, filename=%s)' %
                              (inspect.stack()[1][3], inspect.stack()[1][2], src_md5, filesys, filename))
            return_me = None
            if filename and src_md5:
                dst_md5 = None
                verify_md5 = 'verify /md5 ' + filesys + filename
                dst_md5 = self.do_cli(verify_md5)
                if src_md5 in dst_md5:
                    self.ztp_log.info('MD5 hashes match')
                    return_me = True
                else:
                    self.ztp_log.warning('MD5 hashes do NOT match')
                    return_me = False
            if code_debugging: self.ztp_log.debug('src_md5 is %s dst_md5 is %s' % (src_md5, dst_md5))
            self.ztp_log.info('is %s' % return_me)
            self.ztp_log.debug('returning %s' % return_me)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
            return_me = None
        return return_me

    def extract_ini_section_key(self, ini_file_contents: str = None,
                                section: str = None, section_partial: bool = False,
                                key: str = None):
        """
        Extract some section ... parital or fully .. section from the ini_file_contents.
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
        try:
            self.ztp_log.debug('called from %s@%s with (section=%s, section_partial=%s, key=%s)' %
                               (inspect.stack()[1][3], inspect.stack()[1][2], section, section_partial, key))
            return_me = None
            results = None
            if ini_file_contents:
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
            if results: return_me = results
            self.ztp_log.debug('returning %s' % return_me)
        except configparser.MissingSectionHeaderError as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
            return_me = None
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
            return_me = None
        return return_me

    def extract_ini_structure(self, ini_file_contents: str = None, structure: str = None):
        '''
        Extract some structure section from the ini_file_contents.
        :param ini_file_contents:
        :param structure:
        :return:
        '''
        try:
            self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
            return_me = None
            # only process if we have ini_file_contents and some structure to extract
            if ini_file_contents and structure:
                # if doing advanced debuggging, dump a lot of details
                if code_debugging_TODO: self.ztp_log.debug('ini_file_contents are \n%s' % ini_file_contents)
                # find the sections that partially match structure at the start
                results = self.extract_ini_section_key(ini_file_contents=ini_file_contents,
                                                       section=structure, section_partial=True)
                # if get back a single result, make it a list of one entry
                if isinstance(results, str): results = [results]
                # if get back a list of results, sort for processing
                if isinstance(results, list): results.sort()
                # if doing advanced debuggging, dump a lot of details
                if code_debugging_TODO: self.ztp_log.debug(
                    'ini_file_contents found %s partial sections %s' % (structure, results))
                # results has the list of section names
                structure_results = []
                if results:
                    # step across the list of results and create the individual entries
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
                if structure_results:
                    for entry in structure_results:
                        self.ztp_log.debug('extracted %s' % [entry])
                    return_me = structure_results
            self.ztp_log.debug('returning %s' % return_me)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
            return_me = None
        return return_me


    # def extract_software_tree(self, software_map: list[TransferInfo_tuple] = None, seed_transferit: TransferInfo_tuple = None):
    def extract_software_tree(self, software_map: list = None, seed_transferit: TransferInfo_tuple = None):

        try:
            self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
            return_me = None
            # only process if we have software_tree
            software_tree = {}
            if software_map:
                # convert the software_map into a software_tree dict
                for entry in software_map:
                    hier = entry.section.split(':')
                    # for the top two levels, insert default as the model else software
                    if len(hier) < 4 : hier.append('default')
                    graft = software_tree
                    for level in hier:
                        graftlast = graft
                        if not level in graft: graft[level] = {}
                        graft = graft[level]
                    graftlast.update({level: entry})

                # embedded recursion function for going down tree
                def tree_inherit(tree_node = None, transferit_inherit: TransferInfo_tuple = None):
                    if isinstance(tree_node, TransferInfo_tuple) and isinstance(transferit_inherit, TransferInfo_tuple):
                        tree_node = TransferInfo_tuple_inherit(transferit_parent=transferit_inherit, transferit_child=tree_node)
                    else:
                        # see if the next stem has a default section .. if yes, merge inherit into it
                        stem = 'default'
                        if stem in tree_node:
                            tree_node[stem] = tree_inherit(tree_node=tree_node[stem], transferit_inherit=transferit_inherit)
                            # now switch to the updated defaults for recursion down the tree
                            transferit_inherit = tree_node[stem]
                        for stem in tree_node:
                            tree_node[stem] = tree_inherit(tree_node=tree_node[stem], transferit_inherit=transferit_inherit)
                    return tree_node

                if software_tree and seed_transferit:
                    software_tree = tree_inherit(tree_node=software_tree, transferit_inherit=seed_transferit)
            return_me = software_tree
            self.ztp_log.debug('returning %s' % return_me)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
            return_me = None
        return return_me

    def configure_syslog_and_ntp(self, xfer_servers: list = None):
        try:
            return_me = None
            self.ztp_log.info('called from %s@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
            self.ztp_log.debug('called from %s@%s with (xfer_servers=%s)' %
                          (inspect.stack()[1][3], inspect.stack()[1][2], xfer_servers))
            if xfer_servers:
                for srv in xfer_servers:
                    cmd = None
                    if srv.xfer_mode == 'syslog':   cmd = 'logging host'
                    if srv.xfer_mode == 'ntp':      cmd = 'ntp server'
                    hostname_list = re.split('[\s,]+',srv.hostname)
                    if cmd:
                        for i in hostname_list:
                            self.ztp_log.info('calling do_configure(%s %s)' % (cmd, i))
                            self.do_configure('%s %s' % (cmd,i))
            return_me = True
            self.ztp_log.debug('returning %s' % return_me)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
            return_me = None
        return return_me


if __name__ == "__main__":

    # schedule a reload in case something goes wrong
    reload_time = 2
    cli('enable ; reload in %s reason before calling main()' % reload_time)
    main()

