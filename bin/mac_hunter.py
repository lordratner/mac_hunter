import nmap
from configobj import ConfigObj
import logging, os, subprocess, time

cfd = os.path.dirname(os.path.realpath(__file__))
filename = os.path.join(cfd, "mac_hunter.conf")
config_dict = ConfigObj(filename)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(config_dict['SETTINGS']['log_file']),
    ]
)

log = logging.getLogger(__name__)

def get_ip(mac):
    nm.scan(hosts=config_dict['SETTINGS']['subnet'], arguments='-sP')
    host_list = nm.all_hosts()
    for host in host_list:
        if  'mac' in nm[host]['addresses']:
            if mac == nm[host]['addresses']['mac']:
                log.debug("Found MAC %s on IP %s", mac, host)
                return host
    return False

nm = nmap.PortScanner()
for entry in config_dict:
    if entry == 'SETTINGS':
        continue
    log.debug("Running check for %s, searching for %s", entry, config_dict[entry]['mac'])
    result = get_ip(config_dict[entry]['mac'])
    if result and result != config_dict[entry]['last_ip']:
        update_dict = ConfigObj(config_dict[entry]['file'])
        nesting_length = len(config_dict[entry]['nesting'])
        if nesting_length == 0:
            update_dict[config_dict[entry]['variable']] = result
            config_dict[entry]['last_ip'] = result
        elif nesting_length == 1:
            update_dict[config_dict[entry]['nesting'][0]][config_dict[entry]['variable']] = result
            config_dict[entry]['last_ip'] = result
        elif nesting_length == 2:
            update_dict[config_dict[entry]['nesting'][0]['nesting'][1]][config_dict[entry]['variable']] = result
            config_dict[entry]['last_ip'] = result
        elif nesting_length == 3:          
            update_dict[config_dict[entry]['nesting'][0]['nesting'][1]['nesting'][2]][config_dict[entry]['variable']] = result
            config_dict[entry]['last_ip'] = result
        elif nesting_length == 4:    
            update_dict[config_dict[entry]['nesting'][0]['nesting'][1]['nesting'][2]['nesting'][3]][config_dict[entry]['variable']] = result
            config_dict[entry]['last_ip'] = result
        log.info("Different IP detected, rewriting %s = %s to %s", config_dict[entry]['variable'], result, config_dict[entry]['file'])
        update_dict.write()
        config_dict.write()
        if config_dict[entry]['service'] != '':
            subprocess.run(["systemctl", "restart", config_dict[entry]['service']])
    else: 
        log.debug("IP address %s matches last_ip or is NULL. No changes made", result)
log.info("IP Setter program complete")

                    

