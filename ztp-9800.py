# TODO: docstrings .. top and functions
# TODO: transfrom into a Class construct to make the code more extensible beyond ZTP flow, where main() does not get called if used as import

# Importing cli module
from cli import configure, cli, configurep, executep
import eem
import re
import time
import urllib
import sys
import logging
import os
from logging.handlers import RotatingFileHandler
import subprocess 

# disable log_tofile until logger is initialized, so SYSLOG will still function
log_tofile = False

# set this to trigger code to be upgraded, else empty or False to skip
software_target = "17.09.04a"

xfer_mode_image = 'tftp'
xfer_mode_confg = 'tftp'
my_svr = '192.168.201.211'
xfer_servers = {
    'https':  {'user': '', 'passwd': '', 'uri': my_svr},
    'http':   {'user': '', 'passwd': '', 'uri': my_svr},
    'scp':    {'user': '', 'passwd': '', 'uri': my_svr},
    'ftp':    {'user': '', 'passwd': '', 'uri': my_svr},
    'tftp':   {'uri': my_svr, 'path': 'ztp'},
    'syslog': {my_svr, '10.85.134.6', '10.85.134.6'}
}

# TODO: add SMU and APSP & APDP support
software_mappings = {
    'C9800-80': {
        '17.13.01': {'img': 'C9800-80-universalk9_wlc.17.13.01.SPA.bin', 'md5': '35b30f64fca28112ab903733a44acde0'},
        '17.09.04a': {'img': 'C9800-80-universalk9_wlc.17.09.04a.SPA.bin', 'md5': '9d7e3c491ef1903b51b2e4067522a1f8'},
    },
    'C9800-40': {
        '17.13.01': {'img': 'C9800-40-universalk9_wlc.17.13.01.SPA.bin', 'md5': '35b30f64fca28112ab903733a44acde0'},
        '17.09.04a': {'img': 'C9800-40-universalk9_wlc.17.09.04a.SPA.bin', 'md5': '9d7e3c491ef1903b51b2e4067522a1f8'},
    },
    'C9800-L': {
        '17.13.01': { 'img': 'C9800-L-universalk9_wlc.17.13.01.SPA.bin', 'md5': 'c425f5ae2ceb71db330e8dbc17edc3a8'},
        '17.09.04a': {'img': 'C9800-L-universalk9_wlc.17.09.04a.SPA.bin', 'md5': '70d8a8c0009fc862349a200fd62a0244'},
    },
    'C9800-CL': {
        '17.13.01': { 'img': 'C9800-CL-universalk9.17.13.01.SPA.bin', 'md5': '76c78bdefb2ad689ecc13ed7de3052b9'},
        '17.09.04a': {'img': 'C9800-L-universalk9_wlc.17.09.04a.SPA.bin', 'md5': '70d8a8c0009fc862349a200fd62a0244',
            'APSP': [{'img': 'C9800-CL-universalk9.17.09.04a.CSCwi44524.SPA.apsp.bin','md5': 'f9369a3078ef56b3f70e5c1e16ef4487'}], },
        '17.03.04': { 'img': 'C9800-CL-universalk9.17.09.04a.CSCwh93727.SPA.apsp.bin','md5': 'c92d08d632d23940d03dea0bbf4d5ab5',
            'APDP': [{'img': 'C9800-CL-universalk9.17.03.04.CSCvz10726.SPA.apdp.bin', 'md5': 'a2147aae88f8d28edee0de55fd14b9a9'}],
            'SMU':  [{'img': 'C9800-CL-universalk9.17.03.04.CSCvz30708.SPA.smu.bin',  'md5': '2c618030210be637cbcb24fffd33f37c'}],
            'APSP': [{'img': 'C9800-CL-universalk9.17.03.04.CSCvz58821.SPA.apsp.bin', 'md5': '2d2b9621ebbe7c86b3ac73759ff0652a'},
                     {'img': 'C9800-CL-universalk9.17.03.04.CSCvz17868.SPA.apsp.bin', 'md5': '75e0668eb49e9f370da8005306cd649d'}],
            'WEB':  [{'bun': 'WLC_WEBAUTH_BUNDLE_1.0.zip','md5': 'd9bebd6f10c8b66485a6910eb6113f6c'}], },
    },
}

def main():

    log_tofile = False

    try:
        # TODO: configure SYSLOG setting per software_mapping table

        # switch to enable/disable persistent logger
        if (log_tofile == False):
            filepath = create_logfile()
            configure_logger(filepath)
            log_tofile = True

        print ('###### STARTING ZTP SCRIPT ######\n')
        log_info('STARTING ZTP SCRIPT')

        model = get_model()
        serial = get_serial()

        # only check if software_target has been set
        if software_target:
            software_image = software_mappings[model][software_target]['software_image']
            software_md5_checksum = software_mappings[model][software_target]['software_md5_checksum']
            log_info('Target image is %s with md5 %s' % (software_image, software_md5_checksum))
            update_status, current_version = upgrade_required(software_version)
            log_info('Current version is %s' % current_version)

            if update_status:
                #check if image transfer needed
                if not check_file_exists(software_image):
                    log_info('Attempting to transfer image to switch')
                    file_transfer(xfer_mode_image, xfer_servers, software_image)

                #check to see if the file exists now and check MD5
                # TODO: simplify
                if check_file_exists(software_image):
                    if not verify_dst_image_md5(software_image, software_md5_checksum):
                        log_info('Failed Xfer file does not exist')
                        raise ValueError('Failed Xfer')
                # TODO: look for INSTALL vs BUNDLE mode from software_mappings table and flip if/where needed
                deploy_eem_upgrade_script(software_image,'upgrade' )
                log_info('Performing the upgrade - switch will reload')
                cli('event manager run upgrade')
                timeout_pause = 30
                log_info('Pausing %s seconds to let eem script upgrade trigger a reload' % timeout_pause)
                time.sleep(timeout_pause)
                log_info('EEM upgrade took more than %s seconds to reload the device. Increase the sleep time by few minutes before retrying' % timeout_upgrade)

                # Only do cleanup .. if actually did an upgrade in case someone is doing these steps manually and wnat to keep inactive around
                deploy_eem_cleanup_script('cleanup')
                cli('event manager run cleanup')
                timeout_pause = 30
                log_info('Pausing %s seconds for any config changes to settle in' % timeout_pause)
                time.sleep(timeout_pause)

            else:
               log_info('No upgrade is required')

    # Download and merge config file
        config_file = '%s-%s.cfg' % (model, serial)
        file_transfer(xfer_mode_confg, xfer_servers, config_file)
        log_info('Trying to perform  Day 0 configuration push')
        configure_merge(config_file)
        timeout_pause = 120
        log_info('Pausing %s seconds for any config changes to settle in' % timeout_pause)
        time.sleep(timeout_pause)

        configure('crypto key generate rsa modulus 4096')
        log_info('END OF ZTP SCRIPT')
    
    except Exception as e:
        log_critical('Failure encountered during day 0 provisioning. Aborting ZTP script execution. Error details below')
        log_error(e)
        sys.exit(e)
       

def configure_replace(file,file_system='flash:/' ):
    log_info('Trying to configure_replace(%s, %s)' % (file, file_system))
    config_command = 'configure replace %s%s force' % (file_system, file)
    config_repl = executep(config_command)
    log_debug(config_repl)
    # TODO: sdiff to check if changes took effect
    
def configure_merge(file,file_system='flash:/'):
    log_info('Trying to configure_merge(%s, %s)' % (file, file_system))
    config_command = 'copy %s%s running-config' %(file_system, file)
    config_repl = executep(config_command)
    log_debug(config_repl)
    # TODO: sdiff to check if changes took effect

def check_file_exists(file, file_system='flash:/'):
    log_info('Trying to check_file_exists(%s, %s)' % (file, file_system))
    dir_check = 'dir ' + file_system + file
    results = cli(dir_check)
    if 'No such file or directory' in results:
        log_warn('%s does NOT   exist on %s' % (file, file_system))
        return False
    elif 'Directory of %s%s' % (file_system, file) in results:
        log_info('%s does EXIST on %s' % (file, file_system))
        return True
    elif 'Directory of %s%s' % ('bootflash:/', file) in results:
        log_info('%s does EXIST on %s' % (file, 'bootflash:/'))
        return True
    else:
        log_error('Unexpected output from check_file_exists')
        raise ValueError("Unexpected output from check_file_exists()")

def deploy_eem_cleanup_script(app_label='cleanup'):
    log_info('Trying to deploy_eem_cleanup_script(%s)' % app_label)
    install_command = 'install remove inactive'
    eem_commands = ['event manager applet %s' % app_label,
                    'event none maxrun 600',
                    'action 1.0 cli command "enable"',
                    'action 2.0 cli command "%s" pattern "\[y\/n\]"' % install_command,
                    'action 2.1 cli command "y" pattern "proceed"',
                    'action 2.2 cli command "y"'
                    ]
    results = configurep(eem_commands)
    # TODO: .. check results to make sure they are ALL .. SUCCESS
    log_debug(results)

def deploy_eem_upgrade_script(image, app_label='upgrade'):
    log_info('Trying to deploy_eem_upgrade_script(%s, %s)' % (image, app_label))
    install_command = 'install add file flash://' + image + ' activate commit'
    eem_commands = ['event manager applet %s' % app_label,
                    'event none maxrun 600',
                    'action 1.0 cli command "enable"',
                    'action 2.0 cli command "%s" pattern "\[y\/n\/q\]"' % install_command,
                    'action 2.1 cli command "n" pattern "proceed"',
                    'action 2.2 cli command "y"'
                    ]
    results = configurep(eem_commands)
    # TODO: .. check results to make sure they are ALL .. SUCCESS
    log_debug(results)

def file_transfer(xfer_mode, xfer_servers, file):
  log_info('Trying to file_transfer(%s, %s, %s)' % (xfer_mode, xfer_servers, file))
  # TODO: have this key off of xfer_mode and build the correct copy for http/https/ftp/tftp/scp/etc
  res = cli('copy %s://%s/%s flash:%s' % (xfer_mode, xfer_servers[xfer_mode], file))
  log_debug(res)

def find_certs():
    log_info('Trying to find_certs()')
    certs = cli('show run | include crypto pki')
    if certs:
        certs_split = certs.splitlines()
        certs_split.remove('')
        for cert in certs_split:
            command = 'no %s' % (cert)
            configure(command)

def get_serial():
    log_info('Trying to get_serial()')
    try:
        show_version = cli('show version')
    except Exception as e:
        timeout_pause = 90
        log_info('Pause %s seconds .. and Retry to get_serial()' % timeout_pause)
        time.sleep(timeout_pause)
        show_version = cli('show version')
    try:
        serial = re.search(r"System Serial Number\s+:\s+(\S+)", show_version).group(1)
    except AttributeError:
        serial = re.search(r"Processor board ID\s+(\S+)", show_version).group(1)
    log_info('Found serial %s' % serial)
    return serial

def get_model():
    log_info('Trying to get_model()')
    try:
        show_version = cli('show version')
    except Exception as e:
        timeout_pause = 90
        log_info('Pause %s seconds .. and Retry to get_model()' % timeout_pause)
        time.sleep(timeout_pause)
        show_version = cli('show version')
    model = re.search(r"Model Number\s+:\s+(\S+)", show_version)
    if model != None:
        model = model.group(1)
    else:     
        model = re.search(r"cisco\s(\w+-.*?)\s", show_version)
        if model != None:
          model = model.group(1)
    log_info('Found model %s' % model)
    return model

def get_file_system():
    pass

def update_config(file, file_system='flash:/'):
    log_info('Trying to update_config(%s)' % (file, file_system))
    update_running_config = 'copy %s%s running-config' % (file_system, file)
    # TODO:  .. neutered for now
    save_to_startup = '! write memory'
    log_info('Doing %s' % update_running_config)
    running_config = executep(update_running_config)
    log_debug(running_config)
    log_info('Doing %s' % save_to_startup)
    startup_config = executep(save_to_startup)
    log_debug(startup_config)
    # TODO: .. run sdiff check of running & startup vs config file

def upgrade_required(target_version):
    log_info('Trying to upgrade_required(%s)' % target_version)
    sh_version = cli('show version')
    current_version = re.search(r"Cisco IOS XE Software, Version\s+(\S+)", sh_version).group(1)
    log_info('Current Code Version is %s and Target Code Version is %s' % (current_version, target_version))
    if (target_version == current_version):
        return False, current_version
    else:
        return True, current_version

def verify_dst_image_md5(image, src_md5, file_system='flash:/'):
    log_info('Trying to verify_dst_image_md5(%s, %s, %s)' % (image, src_md5, file_system))
    verify_md5 = 'verify /md5 ' + file_system + image
    log_info('Verifying MD5 for %s' % verify_md5)
    try:
        dst_md5 = cli(verify_md5)
        log_debug(dst_md5)
        if src_md5 in dst_md5:
           log_info('MD5 hashes match')
           return True
        else:
          log_warn('MD5 hashes do NOT match')
          return False
    except Exception as e:
        log_error('MD5 checksum failed due to an exception')
        log_critical(e)
        return False
    
def create_logfile():
    log_info('Trying to create_logfile()')
    # TODO: ... pass a list of files to create and just succeed on the first that worked
    path_1 = '/flash/guest-share/ztp.log'
    path_2 = '/flash/ztp.log'
    try:
        log_info('Creating %s' % path_1)
        path = path_1
        #file_exists = os.path.isfile(path)
        #if(file_exists == False):
          #log_info('%s file does not exist' % path)
        with open(path, 'a+') as fp:
             pass
        return path
    except IOError:
      log_info('Could not create %s. Trying to use %s as alternate' %s (path_1, path_2))
      path = path_2
      #file_exists = os.path.isfile(path)
      #if(file_exists == False):
        # log_info('%s file does not exist' % path)
      with open(path, 'a+') as fp:
             pass
      return path
    except Exception as e:
         log_info('Could not create a log file to proceed')


def configure_logger(path):
    log_info('Trying to configure_logger(%s)' % path)
    log_formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
    logFile = path
    #create a new file > 5 mb size
    log_handler = RotatingFileHandler(logFile, mode='a', maxBytes=5*1024*1024, backupCount=10, encoding=None, delay=0)
    log_handler.setFormatter(log_formatter)
    log_handler.setLevel(logging.INFO)
    ztp_log = logging.getLogger('root')
    ztp_log.setLevel(logging.INFO)
    ztp_log.addHandler(log_handler)

# SYSLOG emergency/0, alert/1, critical/2, error/3, warning/4, notice/5, info/6, debug/7
def log_debug(message):
    eem.action_syslog(message, '7', 'BLAH-DEBUG')
    if(log_tofile == True):
        ztp_log = logging.getLogger('root')
        ztp_log.debug(message)
def log_info(message):
    eem.action_syslog(message, '6', 'BLAH-INFO')
    if (log_tofile == True):
        ztp_log = logging.getLogger('root')
        ztp_log.info(message)
def log_warn(message):
    eem.action_syslog(message, '4', 'BLAH-WARN')
    if (log_tofile == True):
        ztp_log = logging.getLogger('root')
        ztp_log.warn(message)
def log_error(message):
    eem.action_syslog(message, '3', 'BLAH-ERR')
    if (log_tofile == True):
        ztp_log = logging.getLogger('root')
        ztp_log.error(message)
def log_critical(message):
    eem.action_syslog(message, '2', 'BLAH-CRIT')
    if(log_tofile == True):
        ztp_log = logging.getLogger('root')
        ztp_log.critical(message)

if __name__ == "__main__":
    main()
