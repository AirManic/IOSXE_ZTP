# TODO: docstrings .. top and functions TODO: transfrom into a Class construct to make the code more extensible
#  beyond ZTP flow, where main() does not get called if used as import

# Importing cli module
from cli import cli, clip, configure, configurep, execute, executep
import json
import re
from collections import namedtuple
import time
import sys
import inspect
import logging
from logging.handlers import RotatingFileHandler, SysLogHandler
import os


def main():
    try:

        # schedule a reload in case something goes wrong
        cli('reload in 5')

        # create a device so can start to call logger aspects
        # calling it "self".. so it sort of looks and acts a lot like the Class behavior
        self = IOSXEDevice()

        self.ztp_log.info('START')
        self.ztp_log.debug('This device is model % and serial %s' % (self.model, self.serial))

        # config_basic_access() so can SSH to the DHCP address assigned
        self.configure_basic_access()

        # schedule a reload in case something goes wrong
        self.do_cli('reload in 5')

        if self.software_target is not None:
            # check to see if we have a sufficient model prefix match
            # .. look for model with the longest starts with match in software_mappings
            results = [i for i in self.software_mappings.keys() if self.model.startswith(i)]
            self.ztp_log.debug('results of startswith(model) is %s' % results)
            self._fetch_model = max(results, key=len)
            self.ztp_log.debug('_fetch_model is %s' % self._fetch_model)

        self._fetch_software = None
        if self._fetch_model is not None:
        # .. look for software_target in model table
            results = [i for i in self.software_mappings[self._fetch_model].keys() if
                i == self.software_target]
            self._fetch_software = results[0] if len(results) == 1 else ''
            if self._fetch_software is not None:
                self.ztp_log.info('found %s when searching for %s in %s' % (
                    results, self.software_target,
                    self.software_mappings[self._fetch_model].keys()))

        if self._fetch_model is not None and self._fetch_software is not None:
            self._software_image = self.software_mappings[self._fetch_model][self._fetch_software][img]
            self._software_md5 = self.software_mappings[self._fetch_model][self._fetch_software]['md5']
        self.ztp_log.info('target image is %s with md5 %s' % (self._fetch_software, self._software_md5))
        self.ztp_log.info('current version is %s' % self.current_version)

        if self.upgrade_required and False:
            # check if image transfer needed
            if not self.check_file_exists(self._software_image):
                self.ztp_log.info('attempting to transfer image to switch')
                # schedule a reload in case something goes wrong
                self.do_cli('reload in 30')
                transferit = self.TransferInfo_tuple_create()
                transferit = transferit._replace(filename='something')
                self.file_transfer(transferit)

            # check to see if the file exists now and check MD5
            if self.check_file_exists(self._software_image):
                if not self.verify_dst_image_md5(self._software_image, self._software_md5):
                    self.ztp_log.info('failed Xfer file does not exist')
                    raise ValueError('Failed Xfer')

                # TODO: look for INSTALL vs BUNDLE mode from software_mappings table and flip if/where needed
                self.deploy_eem_upgrade_script(self._software_image, 'upgrade')
                self.ztp_log.info('performing the upgrade - switch will reload')

                # schedule a reload in case something goes wrong
                self.do_cli('reload in 90')
                self.do_cli('event manager run upgrade')
                timeout_pause = 3600
                self.ztp_log.info(
                    'pausing %s seconds to let eem script upgrade trigger a reload' % timeout_pause)
                time.sleep(timeout_pause)
                self.ztp_log.info(
                    'eem upgrade took more than %s seconds to reload the device. increase the sleep time by few '
                    'minutes before retrying' % timeout_upgrade)

            # Only do remove_inactive .. if actually did an upgrade in case someone is doing these steps manually and
            # want to keep inactive around
            self.deploy_eem_remove_inactive_script('remove_inactive')
            self.do_cli('event manager run remove_inactive')
            timeout_pause = 30
            self.ztp_log.info('pausing %s seconds for any config changes to settle in' % timeout_pause)
            time.sleep(timeout_pause)

        else:
            self.ztp_log.info('no upgrade is required')

        # TODO: add SMU and APSP & APDP support

        if self.current_chassis.chassis_priority != self.target_chassis.chassis_priority:
            self.change_chassis_priority()
        if self.current_chassis.chassis_number != self.target_chassis.chassis_number:
            self.change_chassis_number()

        self.ztp_log.info('Day0 configuration push')
        self.configure_merge()
        timeout_pause = 120
        self.ztp_log.info('pausing %s seconds for any config changes to settle in' % timeout_pause)
        time.sleep(timeout_pause)
        # TODO:  .. neutered for now
        do_cli('! write memory')

        do_configure('crypto key generate rsa modulus 4096')
        self.ztp_log.info('END')

    except Exception as e:
        self.ztp_log.critical('aborting. failure encountered during day 0 provisioning. error details below')
        self.ztp_log.debug('an error occurred: %s' % type(e).__name__)
        print(e)
        cli('show logging | inc ZTP')
        sys.exit(e)


# TODO: replacing with namedtuple approach
class TransferInfo(dict):
    '''
    characteristics of file to be transferred or host to use
    '''

    def __init__(self, xfer_mode=None, username=None, password=None, hostname=None, port=None,
                 path=None, filename=None, md5=None):
        self.xfer_mode = xfer_mode
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        self.path = path
        self.filename = filename
        self.md5 = md5

    def __str__(self):
        return 'xfer_mode=%s username=%s password=%s hostname=%s port=%s path=%s filename=%s md5=%s' % (
            self.xfer_mode, self.username, self.password, self.hostname, self.port, self.path, self.filename, self.md5)


class IOSXEDevice(dict):
    '''
    IOSXEDevice as currently running guestshell
    '''

    TransferInfo_tuple = namedtuple('TransferInfo_tuple',
                                    'xfer_mode username password hostname port path filename md5')
    TransferInfo_tuple_defaults = {'xfer_mode': None, 'username': None, 'password': None, 'hostname': None,
                                   'port': None, 'path': None, 'filename': None, 'md5': None, }
    def TransferInfo_tuple_create(self,**kwargs):
        transferit = self.TransferInfo_tuple(**self.TransferInfo_tuple_defaults)
        transferit = transferit._replace(**kwargs)
        return transferit

    def __init__(self):
        '''
        create device attributes by extracting off of device
        '''
        self.ztp_log = self.configure_logger()
        # configure_logger() MUST come before all of these, as these all have embedded ztp_log calls
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        # schedule a reload in case something goes wrong
        self.do_cli('reload in 10')

        # get script_name so can know some starting point server to fetch initial defaults
        self.ztp_script = self.get_ztp_script()
        self.xfer_servers = self.fetch_default_xfer_servers()
        # now that servers are loaded.. activate the syslog and ntp references
        self.configure_syslog_and_ntp()

        # create a cache of the show_version
        self.show_version = self.get_show_version()
        # these items use self.show_version
        self.model = self.get_model()
        self.serial = self.get_serial()
        self.current_version = self.get_current_version()

        # transfer the seed_file into flash
        self.seed_file = self.file_transfer(self.get_seed_filename())
        # now load the contents for processing here
        self.seed_file_contents = self.do_cli('term length 0; more flash:%s' % self.seed_file.filename)

        self.config_file = self.file_transfer(self.get_config_filename())
        # now load the contents for processing here
        self.config_file_contents = self.do_cli('term length 0; more flash:%s' % self.config_file.filename)

        # extract the basic access commands from the self.xeed_file and/or self.config_file
        self.basic_access_commands = self.get_basic_access_commands()
        # chassis_priority aspects
        self.current_chassis = self.get_chassis()
        # TODO: extract chassis_priority from desired config file
        self.target_chassis = self.get_target_chassis()

        # TODO: figure out software mapping.. from global default, import from global file, import from device
        #  specific config
        self.software_mappings = self.fetch_default_software_mapping()
        self.software_target = self.process_software_target()

        # depends on self.show_version & self.software_target
        self.upgrade_required = self.check_upgrade_required()

    def get_ztp_script(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        ztp_script = self.TransferInfo_tuple_create()
        show_log = self.do_cli('show logging | inc PNP-6-PNP_SCRIPT_STARTED')
        try:
            '''
            %PNP-6-PNP_SCRIPT_STARTED: Script (http://192.168.201.68/ztp/ztp-9800.py)
            '''
            results = re.search(r"%PNP-6-PNP_SCRIPT_STARTED:\s+Script\s+\((\S+)://(\S+)/(\S+)/(\S+)\)", show_log)
            if results:
                ztp_script = ztp_script._replace(xfer_mode=results.group(1))
                ztp_script = ztp_script._replace(hostname=results.group(2))
                ztp_script = ztp_script._replace(path=results.group(3))
                ztp_script = ztp_script._replace(filename=results.group(4))
                # TODO: TransferInfo_tuple ztp_script cannot translate to %s
                # self.ztp_log.info('found ztp_script %s' % ztp_script)
                self.ztp_log.info('found ztp_script')
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        # TODO: TransferInfo_tuple ztp_script cannot translate to %s
        # self.ztp_log.info('returning ztp_script %s' % ztp_script)
        self.ztp_log.info('returning ztp_script')
        return ztp_script

    def get_show_version(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        show_version = self.do_cli('show version')
        self.ztp_log.info('found show_version \n%s' % show_version)
        self.ztp_log.info('returning show_version \n%s' % show_version)
        return show_version

    def get_model(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        try:
            model = re.search(r"Model Number\s+:\s+(\S+)", self.show_version).group(1)
        except AttributeError:
            model = re.search(r"cisco\s(\w+-.*?)\s", self.show_version).group(1)
        self.ztp_log.info('found model %s' % model)
        self.ztp_log.info('returning model %s' % model)
        return model

    def get_serial(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        try:
            serial = re.search(r"System Serial Number\s+:\s+(\S+)", self.show_version).group(1)
        except AttributeError:
            serial = re.search(r"Processor board ID\s+(\S+)", self.show_version).group(1)
        self.ztp_log.info('found serial %s' % serial)
        self.ztp_log.info('returning serial %s' % serial)
        return serial

    def get_current_version(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        current_version = None
        try:
            results = re.search(r"Cisco IOS XE Software, Version\s+(\S+)", self.show_version)
            if results is not None:
                current_version = results.group(1)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        self.ztp_log.info('found current_version %s' % current_version)
        self.ztp_log.info('returning current_version %s' % current_version)
        return current_version

    def get_seed_filename(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        # start with same place the script came from
        transferit = self.ztp_script
        # change the filename to the seed.yml file
        transferit = transferit._replace(filename='ztp-seed-%s.ini' % self.serial)
        # not really sending back list, but putting list wrapper to let it do %s
        self.ztp_log.info('returning %s' % [transferit])
        return transferit

    def get_config_filename(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        # start with same place the script came from
        transferit = self.ztp_script
        # change filename to the cfg file
        transferit = transferit._replace(filename='%s-%s.cfg' % (self.model, self.serial))
        # TODO: extract a more preferred filename .. and transferit definition
        # not really sending back list, but putting list wrapper to let it do %s
        self.ztp_log.info('returning %s' % [transferit])
        return transferit

    def get_chassis(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        show_chassis = self.do_cli('show chassis')
        chassis_number = None
        chassis_priority = None
        '''
        *1       Active   f4bd.9e56.fa80     1      V02     Ready                0.0.0.0        
        '''
        try:
            results = re.search(r"\*(\d)\s+(\S+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\d)",
                                show_chassis)
            if results is not None:
                chassis_number = results.group(1)
                chassis_priority = results.group(4)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        self.ztp_log.info('found chassis_number %s with chassis_priority %s' % (chassis_number, chassis_priority))
        self.ztp_log.info('returning chassis_number %s with chassis_priority %s' % (chassis_number, chassis_priority))
        chassis_tuple = namedtuple('chassis', 'chassis_number chassis_priority')
        return chassis_tuple(chassis_number, chassis_priority)

    def get_target_chassis(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        # TODO: extract from interpolation of config file
        chassis_number = 2
        chassis_priority = 2
        chassis_tuple = namedtuple('chassis', 'chassis_number chassis_priority')
        return chassis_tuple(chassis_number, chassis_priority)

    def change_chassis_priority(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        self.do_cli('chassis %s priority %s' %
                    (self.current_chassis.chassis_priority, self.target_chassis.chassis_priority))
        self.do_cli('reload')
        timeout_pause = 180
        self.ztp_log.info(
            'pausing %s seconds to let change_chassis_priority() trigger a reload' % timeout_pause)
        time.sleep(timeout_pause)

    def change_chassis_number(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        self.do_cli('chassis %s priority %s' %
                    (self.current_chassis.chassis_number, self.target_chassis.chassis_number))
        self.do_cli('reload')
        timeout_pause = 180
        self.ztp_log.info(
            'pausing %s seconds to let change_chassis_number() trigger a reload' % timeout_pause)
        time.sleep(timeout_pause)

    def fetch_default_software_mapping(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        # TODO: fetch these things from an ini file from the server
        software_mappings = {
            'C9800-80': {
                'software_target': '17.13.01',
                'software_table': {
                    '17,13.01': {
                        'img': self.TransferInfo_tuple_create(filename='C9800-80-universalk9_wlc.17.13.01.SPA.bin',
                                                              md5='35b30f64fca28112ab903733a44acde0'),
                    },
                    '17.09.04a': {
                        'img': self.TransferInfo_tuple_create(filename='C9800-80-universalk9_wlc.17.09.04a.SPA.bin',
                                                              md5='9d7e3c491ef1903b51b2e4067522a1f8'),
                    },
                },
            },
            'C9800-40': {
                'software_target': '17.13.01',
                'software_table': {
                    '17.13.01': {
                        'img': self.TransferInfo_tuple_create(filename='9800-40-universalk9_wlc.17.13.01.SPA.bin',
                                                              md5='35b30f64fca28112ab903733a44acde0'),
                    },
                    '17.09.04a': {
                        'img': self.TransferInfo_tuple_create(filename='C9800-40-universalk9_wlc.17.09.04a.SPA.bin',
                                                              md5='9d7e3c491ef1903b51b2e4067522a1f8'),
                    },
                },
            },
            'C9800-L': {
                'software_target': '17.13.01',
                'software_table': {
                    '17.13.01': {
                        'img': self.TransferInfo_tuple_create(filename='C9800-L-universalk9_wlc.17.13.01.SPA.bin',
                                                              md5='c425f5ae2ceb71db330e8dbc17edc3a8'),
                    },
                    '17.09.04a': {
                        'img': self.TransferInfo_tuple_create(filename='C9800-L-universalk9_wlc.17.09.04a.SPA.bin',
                                                              md5='70d8a8c0009fc862349a200fd62a0244'),
                    },
                    '17.03.04': {
                        'img': self.TransferInfo_tuple_create(filename='C9800-L-universalk9_wlc.17.03.04.SPA.bin',
                                                              md5='c92d08d632d23940d03dea0bbf4d5ab5'),
                        'APDP': self.TransferInfo_tuple_create(filename='',
                                                               md5=''),
                        'SMU': self.TransferInfo_tuple_create(filename='',
                                                              md5=''),
                        'APSP': [
                            self.TransferInfo_tuple_create(filename='',
                                                           md5=''),
                            self.TransferInfo_tuple_create(filename='',
                                                           md5=''),
                        ],
                        'WEB': self.TransferInfo_tuple_create(filename='WLC_WEBAUTH_BUNDLE_1.0.zip',
                                                              md5='d9bebd6f10c8b66485a6910eb6113f6c'),
                    },
                },
            },
            'C9800-L-C-K9': {
                'software_target': '17.13.01',
                'software_table': {
                    '17.13.01': {
                        'img': self.TransferInfo_tuple_create(filename='C9800-L-universalk9_wlc.17.13.01.SPA.bin',
                                                              md5='c425f5ae2ceb71db330e8dbc17edc3a8'),
                    },
                    '17.09.04a': {
                        'img': self.TransferInfo_tuple_create(filename='C9800-L-universalk9_wlc.17.09.04a.SPA.bin',
                                                              md5='70d8a8c0009fc862349a200fd62a0244'),
                    },
                    '17.03.04': {
                        'img': self.TransferInfo_tuple_create(filename='C9800-L-universalk9_wlc.17.03.04.SPA.bin',
                                                              md5='c92d08d632d23940d03dea0bbf4d5ab5'),
                        'APDP': self.TransferInfo_tuple_create(filename='',
                                                               md5=''),
                        'SMU': self.TransferInfo_tuple_create(filename='',
                                                              md5=''),
                        'APSP': [
                            self.TransferInfo_tuple_create(filename='',
                                                           md5=''),
                            self.TransferInfo_tuple_create(filename='',
                                                           md5=''),
                        ],
                        'WEB': self.TransferInfo_tuple_create(filename='WLC_WEBAUTH_BUNDLE_1.0.zip',
                                                              md5='d9bebd6f10c8b66485a6910eb6113f6c'),
                    },
                },
            },
            'C9800-CL': {
                # does not support IOX and guestshell
                'software_target': None,
            },
        }
        self.ztp_log.info('returning software_mappings %s' % software_mappings)
        return software_mappings

    def process_software_target(self):
        '''
        determine best software target from per serial config file, overall software_mapping, else overall target
        :return:
        '''
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        # TODO process tables to yeild serial, software, global pecking order
        software_target = None
        self.ztp_log.info('returning software_target %s' % software_target)
        return software_target

    def get_basic_access_commands(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        # TODO: replace username with information from seed_file
        # extract the basic access commands from the self.xeed_file and/or self.config_file
        configure_basic_access_commands = [
            'username ZTP privilege 15 password Cr8zyM@n',
            'ip domain name ZTP',
            'crypto key generate rsa modulus 4096',
            'line con 0',
            '  logging synchronous',
            'line vty 0 15',
            '  logging synchronous',
            '  login local',
        ]
        return(configure_basic_access_commands)

    def configure_basic_access(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        # TODO: replace username with information from seed_file
        configure_basic_access_commands = [
            'username ZTP privilege 15 password Cr8zyM@n',
            'ip domain name ZTP',
            'crypto key generate rsa modulus 4096',
            'line con 0',
            '  logging synchronous',
            'line vty 0 15',
            '  logging synchronous',
            '  login local',
        ]
        self.do_configure(configure_basic_access_commands)
        return(configure_basic_access_commands)

    def configure_replace(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        self.do_cli('configure replace %s%s force' % ('flash:', self.config_file.filename))
        # TODO: sdiff to check if changes took effect

    def configure_merge(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        self.do_cli('copy %s%s running-config' % ('flash:', self.config_file.filename))
        # TODO: sdiff to check if changes took effect

    def check_file_exists(self, file, file_system='flash:/'):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        dir_check = 'dir ' + file_system + file
        results = self.do_cli(dir_check)
        if 'No such file or directory' in results:
            self.ztp_log.warning('%s does NOT exist on %s' % (file, file_system))
            return False
        elif 'Directory of %s%s' % (file_system, file) in results:
            self.ztp_log.info('%s does EXIST on %s' % (file, file_system))
            return True
        elif 'Directory of %s%s' % ('bootflash:/', file) in results:
            self.ztp_log.info('%s does EXIST on %s' % (file, 'bootflash:/'))
            return True
        else:
            self.ztp_log.error('Unexpected output')
            raise ValueError("Unexpected output")

    def deploy_eem_upgrade_script(self, image, app_label='upgrade'):
        self.ztp_log.info('called from %s()@%s with (image=%s, app_label=%s)' % (
            inspect.stack()[1][3], inspect.stack()[1][2], image, app_label))
        install_command = 'install add file flash:/' + image + ' activate commit'
        eem_commands = ['event manager applet %s' % app_label,
                        'event none maxrun 600',
                        'action 1.0 cli command "enable"',
                        'action 2.0 cli command "%s" pattern "\[y\/n\/q\]"' % install_command,
                        'action 2.1 cli command "n" pattern "proceed"',
                        'action 2.2 cli command "y"'
                        ]
        self.do_configure(eem_commands)

    def deploy_eem_remove_inactive_script(self, app_label='remove_inactive'):
        self.ztp_log.info(
            'called from %s()@%s with (app_label=%s)' % (inspect.stack()[1][3], inspect.stack()[1][2], app_label))
        install_command = 'install remove inactive'
        eem_commands = ['event manager applet %s' % app_label,
                        'event none maxrun 600',
                        'action 1.0 cli command "enable"',
                        'action 2.0 cli command "%s" pattern "\[y\/n\]"' % install_command,
                        'action 2.1 cli command "y" pattern "proceed"',
                        'action 2.2 cli command "y"'
                        ]
        self.do_configure(eem_commands)

    def file_transfer(self, transferit: TransferInfo_tuple):
        self.ztp_log.info('called from %s()@%s with (%s)' % (
            inspect.stack()[1][3], inspect.stack()[1][2], transferit))
        command = 'copy ' + transferit.xfer_mode + '://'
        if transferit.username is not None:
            command = command + transferit.username
            if transferit.password is not None:
                command = command + ':' + transferit.password
            command = command + '@'
        hostname = transferit.hostname
        # TODO: look for leading & trailing '/' and remove
        command = command + hostname
        if transferit.port is not None:
            command = command + ':' + transferit.port
        path = transferit.path
        if path is not None:
            # TODO: look for leading & trailing '/' and remove
            command = command + '/' + path
        filename = transferit.filename
        # TODO: look for leading & trailing '/' and remove
        command = command + '/' + filename
        command = command + ' flash:' + filename
        #TODO: wrap in try/except to know if transfer was OK
        try:
            self.do_cli(command)
        except e as Exception:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
        # not really sending back list, but putting list wrapper to let it do %s
        self.ztp_log.info('returning %s' % [transferit])
        return transferit

    def find_certs(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        certs = self.do_cli('show run | include crypto pki')
        if certs:
            certs_split = certs.splitlines()
            certs_split.remove('')
            for cert in certs_split:
                command = 'no %s' % (cert)
                self.do_configure(command)

    def do_cli(self, command):
        self.ztp_log.info(
            'called from %s()@%s with (command=%s)' % (inspect.stack()[1][3], inspect.stack()[1][2], command))
        results = None
        try:
            results = cli(command)
        except Exception as e:
            self.ztp_log.debug('An error occurred: %s' % type(e).__name__)
            self.ztp_log.debug('(command=%s) and got results \n%s' % (command, results))
            print(e)
            timeout_pause = 90
            self.ztp_log.info('Pause %s seconds .. and Retry %s' % (timeout_pause, command))
            time.sleep(timeout_pause)
            try:
                results = cli(command)
            except Exception as e:
                self.ztp_log.debug('error occurred: %s' % type(e).__name__)
                print(e)
            self.ztp_log.debug('(command=%s) and got results \n%s' % (command, results))
        return results

    def do_configure(self, command):
        self.ztp_log.info(
            'called from %s()@%s with (command=%s)' % (inspect.stack()[1][3], inspect.stack()[1][2], command))
        results = None
        try:
            results = configure(command)
        except Exception as e:
            self.ztp_log.debug('error occurred: %s' % type(e).__name__)
            print(e)
            self.ztp_log.debug('(command=%s) and got results \n%s' % (command, results))
        return results

    def check_upgrade_required(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        self.ztp_log.info(
            'Current Code Version is %s and Target Code Version is %s' % (
                self.current_version, self.software_target))
        if self.current_version == self.software_target:
            return False,
        else:
            return True

    def verify_dst_image_md5(self, image, src_md5, file_system='flash:/'):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        self.ztp_log.info('(%s, %s, %s)' % (image, src_md5, file_system))
        verify_md5 = 'verify /md5 ' + file_system + image
        self.ztp_log.info('%s' % verify_md5)
        dst_md5 = None
        try:
            dst_md5 = self.do_cli(verify_md5)
            if src_md5 in dst_md5:
                self.ztp_log.info('MD5 hashes match')
                return True
            else:
                self.ztp_log.warning('MD5 hashes do NOT match')
                return False
        except Exception as e:
            self.ztp_log.error('MD5 checksum failed due to an exception')
            print(e)
            # TODO: To Be .. or Not To Be .. should this be kept here
            self.ztp_log.debug('src_md5 is %s dst_md5 is %s' % (src_md5, dst_md5))
            return False

    def fetch_default_xfer_servers(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        # TODO: fetch these things from an ini file from the server
        xfer_servers = []
        server = self.TransferInfo_tuple_create(xfer_mode='syslog', hostname='192.168.201.210')
        xfer_servers.append(server)
        server = self.TransferInfo_tuple_create(xfer_mode='syslog', hostname='192.168.201.210')
        xfer_servers.append(server)
        server = self.TransferInfo_tuple_create(xfer_mode='ntp', hostname='192.168.201.254')
        xfer_servers.append(server)
        server = self.TransferInfo_tuple_create(xfer_mode='https', hostname='192.168.201.114', path='ztp')
        xfer_servers.append(server)
        server = self.TransferInfo_tuple_create(xfer_mode='http', hostname='192.168.201.114', path='ztp')
        xfer_servers.append(server)
        server = self.TransferInfo_tuple_create(xfer_mode='scp', hostname='192.168.201.114', path='ztp')
        xfer_servers.append(server)
        server = self.TransferInfo_tuple_create(xfer_mode='ftp', hostname='192.168.201.114', path='ztp')
        xfer_servers.append(server)
        server = self.TransferInfo_tuple_create(xfer_mode='tftp', hostname='192.168.201.114', path='ztp')
        xfer_servers.append(server)

        # start with same place the script came from
        transferit = self.ztp_script
        # change the filename to the ztp-default-xfer-servers.ini file
        transferit = transferit._replace(filename='ztp-default-xfer-servers.ini')
        self.file_transfer(transferit)
        # TODO: extract from file as xfer_servers list
        self.ztp_log.info('returning xfer_servers %s' % xfer_servers)
        return xfer_servers

    def configure_syslog_and_ntp(self):
        self.ztp_log.info('called from %s()@%s' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        self.do_configure('logging trap debugging')
        for srv in self.xfer_servers:
            if srv.xfer_mode == 'syslog':
                self.ztp_log.debug('adding ZTP syslog servers')
                if isinstance(srv.hostname, str): self.do_configure('logging host %s' % srv.hostname)
                if isinstance(srv.hostname, list):
                    for i in srv.hostname: self.do_configure('logging host %s' % i)
            if srv.xfer_mode == 'ntp':
                self.ztp_log.debug('adding ZTP ntp servers')
                if isinstance(srv.hostname, str): self.do_configure('ntp server %s' % srv.hostname)
                if isinstance(srv.hostname, list):
                    for i in srv.hostname: self.do_configure('ntp server %s' % i)

    def configure_logger(self):
        self.ztp_log = logging.getLogger('ZTP')
        self.ztp_log.setLevel(logging.DEBUG)

        def do_guestshell_syslog(record):
            # TODO .. see if this can be fixed
            # with open('/dev/ttyS3', 'w') as fd:
            #   fd.write(record.getMessage())
            # os.system('echo %s > /dev/ttyS3' % record.getMessage())
            try:
                syslog_priority = '5'
                if record.levelname == 'DEBUG': syslog_priority = '7'
                if record.levelname == 'INFO': syslog_priority = '6'
                if record.levelname == 'WARNING': syslog_priority = '4'
                if record.levelname == 'ERROR': syslog_priority = '3'
                if record.levelname == 'CRITICAL': syslog_priority = '2'
                self.eem_action_syslog('%s@%s: %s' % (record.funcName, record.lineno, record.msg),
                                       priority=syslog_priority)
            except Exception as e:
                print('do_guestshell_syslog error occurred: %s' % type(e).__name__)
                print(e)
            return True

        # trigger a SYSLOG message as well
        self.ztp_log.addFilter(do_guestshell_syslog)

        # Create sys.stdout Stream handler
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(
            logging.Formatter('%(asctime)s: %(levelname)s: %(funcName)s@%(lineno)d: %(message)s'))
        self.ztp_log.addHandler(handler)

        # TODO .. see if this can be fixed
        '''
        # Create SysLogHandler handler
        handler = logging.handlers.SysLogHandler()
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter('%(asctime)s: %(levelname)s: %(funcName)s@%(lineno)d: %(message)s'))
        self.ztp_log.addHandler(handler)
        '''

        # TODO .. see if this can be fixed
        '''
        # create a new file > 5 mb size
        handler = logging.handlers.RotatingFileHandler(filename='flash/guest-share/ztp.log',
                                                       mode='a', maxBytes=5 * 1024 * 1024,
                                                       backupCount=10, encoding=None, delay=0)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter('%(asctime)s: %(levelname)s: %(funcName)s@%(lineno)d: %(message)s'))
        self.ztp_log.addHandler(handler)
        '''

        return self.ztp_log

    # SYSLOG emergency/0, alert/1, critical/2, error/3, warning/4, notice/5, info/6, debug/7
    def eem_action_syslog(self, message, priority='6'):
        # trigger a SYSLOG message to the IOS-XE logger
        # transform single/double quotes to tilde ~ eem_commands to avoid delimiter collisions
        new_msg = message.replace('"', '~')
        new_msg = new_msg.replace("'", "~")
        new_msg = new_msg.replace("\n", "; ")
        eem_commands = ['event manager applet eem_action_syslog',
                        'event none maxrun 600',
                        'action 1.0 syslog priority %s msg \"%s\" facility %s' % (priority, new_msg, 'ZTP')]
        # do not call do_configure().. call configure() directly .. otherwise will get loop
        configure(eem_commands)
        # do not call do_cli().. call cli() directly .. otherwise will get loop
        cli('event manager run eem_action_syslog')
        eem_commands = ['no event manager applet eem_action_syslog']
        # do not call do_configure().. call configure() directly .. otherwise will get loop
        configure(eem_commands)


if __name__ == "__main__":
    main()
