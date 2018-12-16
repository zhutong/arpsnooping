import logging
import struct
import collections
import json
import time
import socket
import sys

from pysnmp.entity.rfc3413.oneliner import cmdgen


def send_syslog(message, servers, severity=3, facility=23):
    data = '<%d>%s' % (severity + facility * 8, message)
    for svr in servers:
        syslog_socket.sendto(data, (svr, 514))


def get_logger(severity):
    log_pattern = '%(asctime)s: %(message)s'
    formatter = logging.Formatter(log_pattern)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.setLevel(logging.DEBUG)

    logger = logging.getLogger('SNMP')
    logger.setLevel(severity)
    logger.addHandler(ch)
    logger.propagate = False
    return logger


class SNMPHelper():
    def __init__(self, ip, community='public', port=161, timeout=5, retries=1):
        self.ip = ip
        self.community = community
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.cmd_gen = cmdgen.CommandGenerator()
        self.community_data = cmdgen.CommunityData(community)
        self.transport_target = cmdgen.UdpTransportTarget((ip, port),
                                                          timeout=timeout,
                                                          retries=retries)

    def get_if_index(self):
        cmd_gen = self.cmd_gen
        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            self.community_data,
            self.transport_target,
            0, 20,
            '1.3.6.1.2.1.2.2.1.2',  # interface name
        )

        interface_dict = {}
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    o0, if_name = varBindTableRow[0]
                    mib_tuple = o0._value
                    if mib_tuple[:-1] != (1, 3, 6, 1, 2, 1, 2, 2, 1, 2):
                        break
                    if_index = mib_tuple[-1]
                    interface_dict[if_name._value.decode()] = if_index

        return interface_dict

    def get_arp(self, if_index_list=None):
        arp_oid_str = '.1.3.6.1.2.1.4.35.1.4'  # ipNetToPhysicalPhysAddress in IPMIB
        # arp_oid_str_deprecated = '.1.3.6.1.2.1.3.1.1.2'  # atPhysAddress in RFC1213MIB

        cmd_gen = self.cmd_gen
        error_indication, error_interface_types, error_index, var_bind_table = cmd_gen.bulkCmd(
            self.community_data,
            self.transport_target,
            0, 20,
            arp_oid_str,  # ipNetToPhysicalPhysAddress
        )

        arp_list = []
        if error_indication:
            logger.error('%s: %s' % (error_indication, self.ip))
            raise Exception(error_indication)
        else:
            if error_interface_types:
                logger.error('%s: %s at %s' % (
                    self.ip,
                    error_interface_types.prettyPrint(),
                    error_index and var_bind_table[-1][int(error_index) - 1] or '?'
                ))
            else:
                for varBindTableRow in var_bind_table:
                    oid_value, mac_value = varBindTableRow[0]
                    oid_str = oid_value.prettyPrint()
                    if_index = oid_str.split('.')[-7]
                    if if_index not in if_index_list:
                        continue
                    if not oid_str.startswith(arp_oid_str):
                        break
                    ip_address = '.'.join(oid_str.split('.')[-4:])
                    ss = struct.unpack('!6B', mac_value._value)
                    mac_address = ':'.join(map('{:02x}'.format, ss))
                    arp_list.append((ip_address, mac_address))

        return arp_list


if __name__ == '__main__':
    global logger

    with open('config.json') as f:
        configs = json.load(f)

    hosts = configs['hosts']
    vlans = configs['vlans']

    community = configs['snmp']['community']
    retries = configs['snmp']['retries']
    timeout = configs['snmp']['timeout']
    interval = configs['polling']['interval']

    syslog_servers = configs['syslog']['server'].split(',')
    severity = configs['syslog']['severity']
    syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    logger = get_logger(severity)

    all_arp_dict = collections.defaultdict(list)
    try:
        with open('arp.json') as f:
            all_arp_dict.update(json.load(f))
    except IOError:
        pass

    logger.info('Start ARP monitoring')

    # get ifIndex list for monitored vlans
    host_if_index_dict = {}
    snmp_helper_dict = {}
    for host in hosts:
        snmp_helper = SNMPHelper(host, community, timeout=timeout, retries=retries)
        try:
            if_index_dict = snmp_helper.get_if_index()
            if_index_list = []
            for vlan in vlans:
                if_index_list.append(str(if_index_dict.get('Vlan%d' % vlan)))
            host_if_index_dict[host] = if_index_list
            snmp_helper_dict[host] = snmp_helper
            logger.debug('Got IfIndexes for monitored VLANs: %s' % ', '.join(if_index_list))
        except Exception as e:
            sys.exit(-1)
    try:
        while True:
            for host in hosts:
                snmp_helper = snmp_helper_dict[host]
                if_index_dict = host_if_index_dict[host]

                # get ARP list
                try:
                    arp_list = snmp_helper.get_arp(if_index_list)
                    logger.info('Got %d ARP entries for monitored VLANs from %s', len(arp_list), host)
                    for ip, mac in arp_list:
                        mac_list = all_arp_dict[ip]
                        if not mac_list:
                            logger.info('New ARP entry found for %s: %s' % (ip, mac))
                            all_arp_dict[ip].append(mac)
                        elif mac_list[-1] != mac:
                            msg = 'ARP entry changed for %s: last %s, current %s' % (ip, mac_list[-1], mac)
                            send_syslog(msg, syslog_servers, severity)
                            logger.error(msg)
                            all_arp_dict[ip].append(mac)
                except Exception as e:
                    logger.error(e.message)

            with open('arp.json', 'w') as f:
                json.dump(all_arp_dict, f)
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info('ARP monitoring stopped')