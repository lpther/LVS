__version__ = '0.1.0a'

import sysadmintoolkit
import fcntl
import math
import select
import socket
import struct
import string
import sys
import time
import re
import signal

global plugin_instance

plugin_instance = None


def get_plugin(logger, config):
    '''
    '''
    global plugin_instance

    if plugin_instance is None:
        plugin_instance = LVS(logger, config)

    return plugin_instance


class LVS(sysadmintoolkit.plugin.Plugin):
    def __init__(self, logger, config):
        super(LVS, self).__init__('lvs', logger, config)

        ret, out = sysadmintoolkit.utils.get_status_output('which ipvsadm', self.logger)
        if ret is not 0:
            raise sysadmintoolkit.exception.PluginError('Critical error in lvs plugin: ipvsadm command could not be found', errno=201)

        self.name_resolution = config['name-resolution'].lower() in ['yes']

        ret, out = sysadmintoolkit.utils.get_status_output('ipvsadm -L --daemon', self.logger)
        if out is not '':
            self.syncid = out.splitlines()[0].split('syncid=')[-1].split(')')[0]
            self.sync_int = out.splitlines()[0].split('mcast=')[-1].split(',')[0]
            self.sync_version = sysadmintoolkit.utils.get_status_output('cat /proc/sys/net/ipv4/vs/sync_version', self.logger)[1].strip()
            self.ipvssync = IPVSSync(self.syncid, self.logger, self.name_resolution, interface=self.sync_int, sync_protocol_version=self.sync_version)
        else:
            self.syncid = None
            self.sync_int = None
            self.ipvssync = None

        self.virtual_servers = {}
        self.real_servers = {}

        self.refresh_vs_and_rs_cache()

        self.add_command(sysadmintoolkit.command.ExecCommand('debug lvs', self, self.debug))
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs binding', self, self.display_virtual_servers_mapping))
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs virtual-server', self, self.display_virtual_server_cmd))
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs virtual-server <virtual-server>', self, self.display_virtual_server_cmd))
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs real-server', self, self.display_real_server_cmd))
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs real-server <real-server>', self, self.display_real_server_cmd))
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs connections', self, self.display_connections_cmd))

        self.add_dynamic_keyword_fn('<virtual-server>', self.get_virtual_servers)
        self.add_dynamic_keyword_fn('<real-server>', self.get_real_servers)

        if self.syncid:
            self.add_command(sysadmintoolkit.command.ExecCommand('debug lvs lvssync', self, self.debug_lvs_sync))

    def update_plugin_set(self, plugin_set):
        super(LVS, self).update_plugin_set(plugin_set)

        if 'clustering' in self.plugin_set.get_plugins():
            self.add_command(sysadmintoolkit.command.ExecCommand('show cluster loadbalancer lvs out-of-sync-connections', self, self.display_connections_cmd))

    def refresh_vs_and_rs_cache(self):
        self.logger.debug('Refreshing virtual/real server cache')
        self.virtual_servers = {}
        self.real_servers = {}

        for virtual_server_config in sysadmintoolkit.utils.get_status_output('ipvsadm -S -n | grep ^-A', self.logger)[1].splitlines():
            vs = VirtualService(virtual_server_config)

            if vs.l3_addr not in self.virtual_servers:
                self.virtual_servers[vs.l3_addr] = {'services': {}, 'l3_addr': vs.l3_addr}

            self.logger.debug('Adding virtual service %s to the cache' % str(vs).upper())

            self.virtual_servers[vs.l3_addr]['services']['%s:%s' % (vs.l4_port, vs.l4_proto)] = vs

        for real_server_config in sysadmintoolkit.utils.get_status_output('ipvsadm -S -n | grep ^-a', self.logger)[1].splitlines():
            rs = RealService(real_server_config)

            if rs.l3_addr not in self.real_servers:
                self.real_servers[rs.l3_addr] = {'services': {}, 'l3_addr': rs.l3_addr}

            rs.set_vs(self.virtual_servers[rs.vs_l3_addr]['services']['%s:%s' % (rs.vs_l4_port, rs.l4_proto)])
            self.virtual_servers[rs.vs_l3_addr]['services']['%s:%s' % (rs.vs_l4_port, rs.l4_proto)].add_rs(rs)

            self.logger.debug('Adding real service %s to the cache' % str(rs).upper())

            self.real_servers[rs.l3_addr]['services']['%s:%s:%s:%s' % (rs.l4_port, rs.l4_proto, rs.vs_l3_addr, rs.vs_l4_port)] = rs

        self.refresh_dns_cache()

    def refresh_dns_cache(self):
        if self.name_resolution:
            dns_names = {}

            vs_l3_addrs = self.virtual_servers.keys()
            vs_l3_addrs.sort()

            for vs_l3_addr in vs_l3_addrs:
                try:
                    dns_name = socket.gethostbyaddr(vs_l3_addr)[0].split('.')[0]
                except:
                    continue

                if dns_name not in dns_names:
                    dns_names[dns_name] = []

                dns_names[dns_name].append(self.virtual_servers[vs_l3_addr])

            for dns_name in dns_names:
                if len(dns_names[dns_name]) is 1:
                    self.virtual_servers[dns_name] = dns_names[dns_name][0]
                else:
                    for index in range(len(dns_names[dns_name])):
                        self.virtual_servers['%s-vip%s' % (dns_name, index + 1)] = dns_names[dns_name][index]

            rs_l3_addrs = self.real_servers.keys()
            rs_l3_addrs.sort()

            for rs_l3_addr in rs_l3_addrs:
                try:
                    dns_name = socket.gethostbyaddr(rs_l3_addr)[0].split('.')[0]
                except:
                    self.real_servers[rs_l3_addr] = 'unknown'
                    continue

                self.real_servers[dns_name] = self.real_servers[rs_l3_addr]
                self.real_servers[dns_name]['dns_name'] = dns_name

    def print_virtual_server_mapping(self, virtual_server):
        if virtual_server not in self.virtual_servers:
            self.logger.warning('Unknown virtual server %s' % virtual_server)
            print 'Unknown virtual server!'
            return 1

        vs_string = '    %s' % virtual_server

        if self.name_resolution:
            vs_string = '%s (%s)' % (vs_string, self.virtual_servers[virtual_server]['l3_addr'])

        print '%s:' % vs_string
        print

        service_keys = self.virtual_servers[virtual_server]['services'].keys()
        service_keys.sort()

        for service in service_keys:
            vs_object = self.virtual_servers[virtual_server]['services'][service]
            real_server_services_keys = vs_object.rs.keys()
            real_server_services_keys.sort()

            for i in range(len(real_server_services_keys)):
                if i is 0:
                    if self.name_resolution:
                        port = service.split(':')[0]
                        proto = service.split(':')[1]
                        portname = sysadmintoolkit.utils.get_l4_portname(int(port), proto.lower())
                        service_desc_str = '%s/%s/%s' % (portname, port, proto)
                        service_str = '      %s' % (service_desc_str.rjust(20))
                    else:
                        service_str = '      %s' % (service.upper().rjust(9).replace(':', '/'))

                    print '%s %s' % (service_str, vs_object.lb_algo.rjust(5)),
                else:
                    print ' ' * len('%s %s' % (service_str, vs_object.lb_algo.rjust(5))),

                print '->',

                rs_object = self.virtual_servers[virtual_server]['services'][service].rs[real_server_services_keys[i]]

                if self.name_resolution:
                    rs_prefix = '%s/' % self.real_servers[rs_object.l3_addr]['dns_name'].rjust(13)
                else:
                    rs_prefix = ''

                if rs_object.weight is 0:
                    state = 'failed'
                elif rs_object.weight is 1:
                    state = 'active'
                else:
                    state = 'active  weight:%s' % rs_object.weight

                print '%s%s:%s %s  %s' % (rs_prefix, rs_object.l3_addr.rjust(15), rs_object.l4_port.ljust(5), \
                                         rs_object.fwding_method.lower().ljust(6), state)

            print

    def display_virtual_server(self, virtual_server, connections):
        self.logger.debug('Displaying virtual server %s' % (virtual_server))

        vs_string = '    %s' % virtual_server

        if self.name_resolution:
            vs_string = '%s   IP: %s' % (vs_string.ljust(20), self.virtual_servers[virtual_server]['l3_addr'].rjust(15))

        print '%s' % vs_string,

        if not sysadmintoolkit.utils.is_ipv4_addr(virtual_server):
            vs_ip_hex = sysadmintoolkit.utils.get_hexstr_from_ipv4_addr(self.virtual_servers[virtual_server]['l3_addr'])
        else:
            vs_ip_hex = sysadmintoolkit.utils.get_hexstr_from_ipv4_addr(virtual_server)

        vs_connections = re.findall(r"^[A-Z]* [A-F,0-9]* [A-F,0-9]* %s .*" % vs_ip_hex, connections, re.MULTILINE)

        print '        Total Connections: %s' % len(vs_connections)
        print

        service_keys = self.virtual_servers[virtual_server]['services'].keys()
        service_keys.sort()

        for service in service_keys:
            vs_object = self.virtual_servers[virtual_server]['services'][service]

            port = service.split(':')[0]
            proto = service.split(':')[1]

            l4_port_hex = sysadmintoolkit.utils.get_hexstr_from_l4_port(vs_object.l4_port)

            if self.name_resolution:
                portname = sysadmintoolkit.utils.get_l4_portname(int(port), proto.lower())
                service_desc_str = '%s/%s/%s' % (portname, port, proto)
                service_str = '      %s' % (service_desc_str.rjust(20))
            else:
                service_str = '      %s' % (service.upper().rjust(9).replace(':', '/'))

            print '%s             Scheduler: %s' % (service_str, lb_algo_map[vs_object.lb_algo].rjust(5)),

            service_connections = re.findall("^%s [A-F,0-9]* [A-F,0-9]* %s %s .*" % \
                                             (vs_object.l4_proto.upper(), vs_ip_hex, l4_port_hex), '\n'.join(vs_connections), re.MULTILINE)

            print '        Connections: %s' % len(service_connections)

            est_connections = re.findall("^%s [A-F,0-9]* [A-F,0-9]* %s %s .* ESTABLISHED" % \
                                             (vs_object.l4_proto.upper(), vs_ip_hex, l4_port_hex), '\n'.join(service_connections), re.MULTILINE)
            finw_connections = re.findall("^%s [A-F,0-9]* [A-F,0-9]* %s %s .* FIN_WAIT" % \
                                             (vs_object.l4_proto.upper(), vs_ip_hex, l4_port_hex), '\n'.join(service_connections), re.MULTILINE)
            closed_connections = re.findall("^%s [A-F,0-9]* [A-F,0-9]* %s %s .* CLOSE" % \
                                             (vs_object.l4_proto.upper(), vs_ip_hex, l4_port_hex), '\n'.join(service_connections), re.MULTILINE)

            print
            print '%s Established: %s' % (' ' * len(service_str), len(est_connections))
            print '%s    Fin-Wait: %s' % (' ' * len(service_str), len(finw_connections))
            print '%s     Closing: %s' % (' ' * len(service_str), len(closed_connections))
            print

    def display_real_server(self, real_server, connections):
        self.logger.debug('Displaying real server %s' % (real_server))

        rs_string = '    %s' % real_server

        if self.name_resolution:
            rs_string = '%s   IP: %s' % (rs_string.ljust(20), self.real_servers[real_server]['l3_addr'].rjust(15))

        print '%s' % rs_string,

        if not sysadmintoolkit.utils.is_ipv4_addr(real_server):
            rs_ip_hex = sysadmintoolkit.utils.get_hexstr_from_ipv4_addr(self.real_servers[real_server]['l3_addr'])
        else:
            rs_ip_hex = sysadmintoolkit.utils.get_hexstr_from_ipv4_addr(real_server)

        rs_connections = re.findall(r"^[A-Z]* [A-F,0-9]* [A-F,0-9]* [A-F,0-9]* [A-F,0-9]* %s .*" % rs_ip_hex, connections, re.MULTILINE)

        print '        Total Connections: %s' % len(rs_connections)
        print

        service_keys = self.real_servers[real_server]['services'].keys()
        service_keys.sort()

        for service in service_keys:
            rs_object = self.real_servers[real_server]['services'][service]

            port = service.split(':')[0]
            proto = service.split(':')[1]
            vs_l3_addr = service.split(':')[2]
            vs_l4_port = service.split(':')[3]

            l4_port_hex = sysadmintoolkit.utils.get_hexstr_from_l4_port(rs_object.l4_port)
            vs_ip_hex = sysadmintoolkit.utils.get_hexstr_from_ipv4_addr(vs_l3_addr)
            vs_l4_port_hex = sysadmintoolkit.utils.get_hexstr_from_l4_port(vs_l4_port)

            if self.name_resolution:
                portname = sysadmintoolkit.utils.get_l4_portname(int(port), proto.lower())
                service_desc_str = '%s/%s/%s' % (portname, port, proto)
                service_str = '      %s             ' % (service_desc_str.rjust(20))
            else:
                service_str = '      %s             ' % (service.upper().rjust(9).replace(':', '/'))

            service_connections = re.findall(r"^%s [A-F,0-9]* [A-F,0-9]* %s %s %s %s .*" % \
                                             (rs_object.l4_proto.upper(), vs_ip_hex, vs_l4_port_hex, rs_ip_hex, vs_l4_port_hex), '\n'.join(rs_connections), re.MULTILINE)

            print '%s Virtual Server: %s:%s  Connections: %s' % (service_str, vs_l3_addr.rjust(15), vs_l4_port.ljust(5), len(service_connections))
            print
            print '%s Weight:%s  Forwarding Method: %s' % (' ' * len(service_str), str(rs_object.weight).ljust(5), packet_forwarding_method_desc[rs_object.fwding_method])

            est_connections = re.findall(r"^%s [A-F,0-9]* [A-F,0-9]* %s %s %s %s ESTABLISHED" % \
                                             (rs_object.l4_proto.upper(), vs_ip_hex, vs_l4_port_hex, rs_ip_hex, vs_l4_port_hex), '\n'.join(service_connections), re.MULTILINE)
            finw_connections = re.findall(r"^%s [A-F,0-9]* [A-F,0-9]* %s %s %s %s FIN_WAIT" % \
                                             (rs_object.l4_proto.upper(), vs_ip_hex, vs_l4_port_hex, rs_ip_hex, vs_l4_port_hex), '\n'.join(service_connections), re.MULTILINE)
            closed_connections = re.findall(r"^%s [A-F,0-9]* [A-F,0-9]* %s %s %s %s CLOSE" % \
                                             (rs_object.l4_proto.upper(), vs_ip_hex, vs_l4_port_hex, rs_ip_hex, vs_l4_port_hex), '\n'.join(service_connections), re.MULTILINE)

            print
            print '%s Established: %s' % (' ' * len(service_str), len(est_connections))
            print '%s    Fin-Wait: %s' % (' ' * len(service_str), len(finw_connections))
            print '%s     Closing: %s' % (' ' * len(service_str), len(closed_connections))
            print

    # Dynamic keywords

    def get_virtual_servers(self, dyn_keyword=None):
        '''
        Returns the list of virtual servers
        '''
        virtual_servers = self.virtual_servers.keys()
        virtual_servers.sort()

        vsmap = {}

        for vs in virtual_servers:
            if not sysadmintoolkit.utils.is_ipv4_addr(vs):
                vsmap[vs] = 'Virtual server %s' % self.virtual_servers[vs]['l3_addr']
            else:
                vsmap[vs] = 'Virtual server'

        return vsmap

    def get_real_servers(self, dyn_keyword=None):
        '''
        Returns the list of real servers
        '''
        real_servers = self.real_servers.keys()
        real_servers.sort()

        rsmap = {}

        for rs in real_servers:
            if not sysadmintoolkit.utils.is_ipv4_addr(rs):
                rsmap[rs] = 'Real server %s' % self.real_servers[rs]['l3_addr']
            else:
                rsmap[rs] = 'Real server'

        return rsmap

    # Sysadmin-toolkit commands

    def display_connections_cmd(self, line, mode):
        '''
        Displays connection table
        '''
        print sysadmintoolkit.utils.get_status_output('ipvsadm -L -n -c', self.logger)[1]


    def display_virtual_servers_mapping(self, line, mode):
        '''
        Displays virtual servers to real servers mapping
        '''
        virtual_servers_keys = self.virtual_servers.keys()
        virtual_servers_keys.sort()

        for virtual_server in virtual_servers_keys:
            if self.name_resolution and sysadmintoolkit.utils.is_ipv4_addr(virtual_server):
                continue

            self.print_virtual_server_mapping(virtual_server)

    def display_virtual_server_cmd(self, line, mode):
        '''
        Displays Virtual Server information
        '''

        if 'virtual-server' == line.split()[-1]:
            virtual_servers_keys = self.virtual_servers.keys()
            virtual_servers_keys.sort()
        else:
            virtual_servers_keys = [line.split()[line.split().index('virtual-server') + 1]]

        connections = sysadmintoolkit.utils.get_status_output('grep -v ^Pro /proc/net/ip_vs_conn', self.logger)[1]

        for vs in virtual_servers_keys:
            if self.name_resolution and sysadmintoolkit.utils.is_ipv4_addr(vs):
                continue

            self.display_virtual_server(vs, connections)
            print

    def display_real_server_cmd(self, line, mode):
        '''
        Displays Real Server information
        '''

        if 'real-server' == line.split()[-1]:
            real_servers_keys = self.real_servers.keys()
            real_servers_keys.sort()
        else:
            real_servers_keys = [line.split()[line.split().index('real-server') + 1]]

        connections = sysadmintoolkit.utils.get_status_output('grep -v ^Pro /proc/net/ip_vs_conn', self.logger)[1]

        for rs in real_servers_keys:
            if self.name_resolution and sysadmintoolkit.utils.is_ipv4_addr(rs):
                continue

            self.display_real_server(rs, connections)
            print


    def debug(self, line, mode):
        '''
        Displays LVS configuration and state
        '''
        print 'LVS plugin configuration and state:'
        print
        print '  LVS plugin version: %s' % __version__
        print '  ipvsadm version: %s' % sysadmintoolkit.utils.get_status_output('ipvsadm -v', self.logger)[1]
        print
        print '  Name resolution: %s' % self.name_resolution
        print '  Clustering support: %s' % ('clustering' in self.plugin_set.get_plugins())
        print

        if self.syncid:
            print '  Connection synchronization information:'
            print '       sync version: %s' % self.sync_version
            print '             syncid: %s' % self.syncid
            print '    mcast interface: %s' % self.sync_int
        else:
            print '  No connection synchronization support'
        print

    def debug_lvs_sync(self, line, mode):
        '''
        Dump all LVS Sync packets seen on the Sync Daemon interface
        '''
        def sigint_handler(signum, frame):
            raise KeyboardInterrupt

        old_sigint_action = signal.signal(signal.SIGINT, sigint_handler)

        try:
            print 'Displaying lvs sync connections seen on interface %s:' % self.sync_int
            self.ipvssync.debug()

        finally:
            signal.signal(signal.SIGINT, old_sigint_action)


# ----- LVS plugin classes -----

l4_proto_map = {'-t':'tcp', '-u':'udp', '-f':'fwmark'}
lb_algo_map = {'rr': 'Robin Robin', 'wrr': 'Weighted Round Robin', 'lc': 'Least-Connection', 'wlc': 'Weighted Least-Connection', \
               'lblc': 'Locality-Based Least-Connection', 'lblcr': 'Locality-Based Least-Connection with Replication', \
               'dh': 'Destination Hashing', 'sh': 'Source Hashing', 'sed': 'Shortest Expected Delay', \
               'nq': 'Never Queue' }
packet_forwarding_method = {'-m': 'MASQ', '-g': 'DROUTE', '-i': 'TUNNEL'}
packet_forwarding_method_desc = {'MASQ': 'NAT (Masquerading)', 'DROUTE': 'Direct Routing (Gatewaying)', 'TUNNEL': 'Tunneling (IP-IP Encapsulation)'}

class VirtualService(object):
    def __init__(self, ipvsadm_config_line):
        self.l3_addr, self.l4_port = tuple(ipvsadm_config_line.split()[2].split(':'))
        self.l4_proto = l4_proto_map[ipvsadm_config_line.split()[1]]
        self.lb_algo = ipvsadm_config_line.split()[4]
        self.rs = {}

    def add_rs(self, rs_object):
        self.rs['%s:%s:%s' % (rs_object.l3_addr, rs_object.l4_port, rs_object.l4_proto)] = rs_object

    def __str__(self):
        return '%s:%s %s %s' % (self.l3_addr, self.l4_port, self.l4_proto, self.lb_algo)

class RealService(object):
    def __init__(self, ipvsadm_config_line):
        self.vs_l3_addr, self.vs_l4_port = tuple(ipvsadm_config_line.split()[2].split(':'))
        self.l3_addr, self.l4_port = tuple(ipvsadm_config_line.split()[4].split(':'))
        self.l4_proto = l4_proto_map[ipvsadm_config_line.split()[1]]
        self.fwding_method = packet_forwarding_method[ipvsadm_config_line.split()[5]]
        self.weight = int(ipvsadm_config_line.split()[7])
        self.vs_object = None

    def set_vs(self, vs_object):
        self.vs_object = vs_object

    def __str__(self):
        return '%s:%s -> %s:%s %s %s %s' % (self.vs_l3_addr, self.vs_l4_port, self.l3_addr.rjust(15), self.l4_port.ljust(5), \
                                            self.l4_proto.ljust(5), self.fwding_method.ljust(6), str(self.weight).rjust(3))

# ----- LVSSYNC Library -----

# lvssync constants
LVSSYNC_MIN_SLEEP = 0.25  # In debugging mode, how much time to sleep before checking the buffer
LVSSYNC_FQDN_NR = False  # Set to True for fully qualified name resolution

# ip_vs_sync constants
MCAST_GRP = '224.0.0.81'
MCAST_GRP_TTL = 1
MCAST_PORT = 8848

IP_VS_CONN_HDRLEN = 8
IP_VS_CONN_CONNHDRLEN = 8
IP_VS_CONN_CONNLEN = 36  # Without parameters

IP_VS_CONN_F_MASQ = {'flag': 0x0000 , 'flagname': 'MASQ' }
IP_VS_CONN_F_LOCALNODE = {'flag': 0x0001 , 'flagname': 'LOCALNODE' }
IP_VS_CONN_F_TUNNEL = {'flag': 0x0002 , 'flagname': 'TUNNEL' }
IP_VS_CONN_F_DROUTE = {'flag': 0x0003 , 'flagname': 'DROUTE' }
IP_VS_CONN_F_BYPASS = {'flag': 0x0004 , 'flagname': 'BYPASS' }
IP_VS_CONN_F_SYNC = {'flag': 0x0020 , 'flagname': 'SYNC' }
IP_VS_CONN_F_HASHED = {'flag': 0x0040 , 'flagname': 'HASHED' }
IP_VS_CONN_F_NOOUTPUT = {'flag': 0x0080 , 'flagname': 'NOOUTPUT' }
IP_VS_CONN_F_INACTIVE = {'flag': 0x0100 , 'flagname': 'INACTIVE' }
IP_VS_CONN_F_OUT_SEQ = {'flag': 0x0200 , 'flagname': 'F_OUT_SEQ' }
IP_VS_CONN_F_IN_SEQ = {'flag': 0x0400 , 'flagname': 'F_IN_SEQ' }
IP_VS_CONN_F_NO_CPORT = {'flag': 0x0800 , 'flagname': 'NO_CPORT' }
IP_VS_CONN_F_TEMPLATE = {'flag': 0x1000 , 'flagname': 'TEMPLATE' }
IP_VS_CONN_F_ONE_PACKET = {'flag': 0x2000 , 'flagname': 'ONE_PACKET' }

IP_VS_TCP_S_CONNECTION_STATES = ['NONE', 'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT', \
                                'TIME_WAIT', 'CLOSE', 'CLOSE_WAIT', 'LAST_ACK', 'LISTEN', 'SYNACK', 'LAST']

IP_VS_F_FWD_METHOD = ['MASQ', 'LOCALNODE', 'TUNNEL', 'DROUTE', 'BYPASS']

IP_VS_F_BOOL = [IP_VS_CONN_F_SYNC, IP_VS_CONN_F_HASHED, IP_VS_CONN_F_NOOUTPUT, IP_VS_CONN_F_INACTIVE, IP_VS_CONN_F_OUT_SEQ, IP_VS_CONN_F_IN_SEQ, IP_VS_CONN_F_NO_CPORT, IP_VS_CONN_F_TEMPLATE, IP_VS_CONN_F_ONE_PACKET]

# other constants
SIOCGIFADDR = 0x8915

class SyncConnectionHeader(object):
    def __init__(self, logger, socket_buffer=None):
        self.initialized = False

        self.logger = logger

        self.size = None
        self.reserved = None
        self.syncid = None
        self.nr_conns = None
        self.version = None
        self.spare = None

        if socket_buffer:
            self.decode_from_socket(socket_buffer)
            self.logger.debug('Decoded head from socket buffer: %s' % self)

    def __str__(self):
        return str(self.syncid).center(6)

    def decode_from_socket(self, socket_buffer):
        reserved , syncid , rawsize , nr_conns, version, spare = struct.unpack('BBHBbH', socket_buffer[0:IP_VS_CONN_HDRLEN])

        self.size = socket.ntohs(rawsize)
        self.reserved = reserved
        self.syncid = syncid
        self.nr_conns = nr_conns
        self.version = version
        self.spare = spare

        self.initialized = True

class SyncConnection(object):
    def __init__(self, logger, name_resolution, ipvsadm_conn_str=None, socket_buffer=None):
        self.initialized = False

        self.logger = logger
        self.name_resolution = name_resolution

        self.type = None
        self.protocol = None
        self.version = None
        self.size = None
        self.flags = None
        self.state = None
        self.cport = None
        self.vport = None
        self.dport = None
        self.timeout = None
        self.caddr = None
        self.vaddr = None
        self.daddr = None

        if socket_buffer:
            self.decode_from_socket(socket_buffer)
            self.logger.debug('Decoded connection from socket buffer: %s' % self)

    def __str__(self):
        # Get protocol name
        if self.protocol is socket.SOL_TCP:
            protocol_str = 'TCP'

        elif self.protocol is socket.SOL_UDP:
            protocol_str = 'UDP'

        else:
            protocol_str = str(self.protocol)

        # Get expiration format
        expire = '%3d:%2s' % (self.timeout / 60, str(self.timeout % 60).zfill(2))

        # Get s/v/d client:protocol pair
        caddr, vaddr , daddr = (self.caddr, self.vaddr, self.daddr)
        addrspacer = ''

        if self.name_resolution:
            addrspacer = ' '
            try:
                caddr = socket.gethostbyaddr(caddr)[0]

                if not LVSSYNC_FQDN_NR:
                    caddr = caddr.split('.')[0]
            except:
                pass

            try:
                vaddr = socket.gethostbyaddr(vaddr)[0]

                if not LVSSYNC_FQDN_NR:
                    vaddr = vaddr.split('.')[0]
            except:
                pass

            try:
                daddr = socket.gethostbyaddr(daddr)[0]

                if not LVSSYNC_FQDN_NR:
                    daddr = daddr.split('.')[0]
            except:
                pass

        source = '%s:%s' % (caddr, self.cport) + addrspacer
        virtual = '%s:%s' % (vaddr, self.vport) + addrspacer
        destination = '%s:%s' % (daddr, self.dport) + addrspacer

        return '%s%s%s%s%s%s%s' % (string.center(protocol_str, 4), string.center(expire, 7), \
                                                string.center(self.state, 13), string.center(source, 22), \
                                                string.center(virtual, 22), string.center(destination, 22), ' '.join(self.flags))

    def decode_from_socket(self, socket_buffer):
        conn_type, protocol, ver_size, flags, state, cport, \
        vport, dport, fwmark, timeout, caddr, vaddr, daddr = struct.unpack('BBHIHHHHIIIII', socket_buffer[:IP_VS_CONN_CONNLEN])

        self.type = conn_type
        self.protocol = protocol
        self.version = socket.ntohs(ver_size) >> 12
        self.size = socket.ntohs(ver_size) & 0b0000111111111111
        self.flags = self.decode_flags(socket.ntohl(flags))
        self.state = IP_VS_TCP_S_CONNECTION_STATES[socket.ntohs(state)]
        self.cport = socket.ntohs(cport)
        self.vport = socket.ntohs(vport)
        self.dport = socket.ntohs(dport)
        self.timeout = int(socket.ntohl(timeout))
        self.caddr = self.unsigned_int_to_ip(socket.ntohl(caddr))
        self.vaddr = self.unsigned_int_to_ip(socket.ntohl(vaddr))
        self.daddr = self.unsigned_int_to_ip(socket.ntohl(daddr))

        self.initialized = True

    def unsigned_int_to_ip(self, unsigned_int):
        '''
        Returns dotted quad ip str
        '''
        a = (unsigned_int & 0xff000000) >> 24
        b = (unsigned_int & 0x00ff0000) >> 16
        c = (unsigned_int & 0x0000ff00) >> 8
        d = unsigned_int & 0x000000ff
        return '%s.%s.%s.%s' % (a, b, c, d)

    def ip_to_unsigned_int(self, dotted_quad_ip):
        '''
        Returns unsigned int from dotted quad
        '''
        unsigned_int = 0x00000000
        for quad_id in range(4):
            quad = dotted_quad_ip.split('.')[quad_id]

            unsigned_int += int(quad) << ((8 * (3 - quad_id)))

        return unsigned_int

    def decode_flags(self, rawflags):
        flags = []

        flags += [ IP_VS_F_FWD_METHOD[rawflags & 0x0007] ]

        for f in IP_VS_F_BOOL:
            if rawflags & f['flag']:
                flags.append(f['flagname'])

        return flags

    def encode_flags(self, flagslist):
        rawflags = 0x0000

        for f in flagslist:
            rawflags = rawflags | f

        return rawflags


class IPVSSync(object):
    '''
    ipvs sync library

    Use this library to send mcast messages to a group of LVS servers to
    synchronize their client tables. The number of connections per second
    can be tuned to prevent choking servers/upsetting network people.

    For what type of environment is it designed:
    -Direct Routing LVS cluster
    -Symmetric cluster
    -Any number of nodes

    What is not implemented:
    -Connection parameters
    -fwmark
    -Extensive debugging options
    -ipv6
    -Connection options are not changeable (fixed at updating/adding
     a connection)
    -No real validation of input data
    -No real error handling

    What is not tested:
    -MASQ,TUNNEL modes

    Reference for packet structure:
    http://lxr.free-electrons.com/source/net/netfilter/ipvs/ip_vs_sync.c

    '''

    def __init__(self, syncid, logger, name_resolution, interface=None, sync_protocol_version=1):
        '''
        Main class to receive or send ipvs sync connections

        interface   str     interface to bind the mcast socket
                            defaults to socket.INADDR_ANY
        syncid      int     syncid instance identifier
        '''
        self.socket = None
        self.recvbuffer = ''
        self.sendbuffer = ''

        self.interface = interface
        self.interfaceaddress = None
        self.interfacemtu = 1500
        self.maxmcastmessage = self.interfacemtu - 68  # Safe header room for IP + UDP

        self.name_resolution = name_resolution

        self.syncid = syncid
        self.sync_protocol_version = sync_protocol_version
        self.logger = logger

        self.logger.debug('IPVSSync instance created. syncid=%s interface=%s version=%s' % (self.syncid, self.interface, self.sync_protocol_version))

    def get_send_conn_list_duration(self, connlist, connspersec=250):
        '''
        Returns the number of seconds if should take to send this list of connections
        '''
        maxconnpermessage = int(math.floor((self.maxmcastmessage - IP_VS_CONN_HDRLEN) / IP_VS_CONN_CONNLEN))
        maxconnpermessage = min(maxconnpermessage, connspersec)

        return int(math.ceil(float(len(connlist)) / connspersec)) - 1

    def send_conn_list(self, connlist, connspersec=250):
        '''
        Sends the connlist of connections to the lvs mcast group,
        to update all lvs on the network

        connlist    list    [conn, conn, ... conn]
        connspersec int     Upper limit of connections per second to transmit

        conn        dict    {   'protocol'      : int of socket.SOL_TCP | socket.SOL_UDP | other ... ,
                                'director_type' : str in IP_VS_F_FWD_METHOD
                                'timeout'       : int in seconds
                                'cport'         : int client tcp port
                                'vport'         : int virtual tcp port
                                'dport'         : int destination tcp port
                                'caddr'         : str client ipv4 addr in dotted quad
                                'vaddr'         : str virtual ipv4 addr in dotted quad
                                'daddr'         : str destination ipv4 addr in dotted quad
                            }
        '''
        if self.socket == None:
            self.init_socket()

        maxconnpermessage = int(math.floor((self.maxmcastmessage - IP_VS_CONN_HDRLEN) / IP_VS_CONN_CONNLEN))
        maxconnpermessage = min(maxconnpermessage, connspersec)

        nr_sent_this_second = 0
        last_sent_time = time.time()

        while True:
            if len(connlist) == 0:
                break
            elif nr_sent_this_second >= connspersec:
                time.sleep(LVSSYNC_MIN_SLEEP)

                now = time.time()
                if now - last_sent_time > 1.0:
                    nr_sent_this_second = 0
            else:
                nr_conns = min(len(connlist), maxconnpermessage)

                # Generate the buffer data for the connections to send with this message
                buffconns = self.encode_connlist(connlist[:nr_conns])

                reserved = 0
                syncid = self.syncid
                size = socket.htons(IP_VS_CONN_HDRLEN + len(buffconns))
                version = 1
                spare = 0

                buffhdr = struct.pack('BBHBbH', reserved, syncid, size, nr_conns, version, spare)

                self.socket.sendto(buffhdr + buffconns, (MCAST_GRP, MCAST_PORT))

                nr_sent_this_second += nr_conns
                last_sent_time = time.time()
                connlist = connlist[nr_conns:]

        self.shut_socket()


    def debug(self):
        '''
        Binds to the ipvs sync multicast address and dumps received packets
        to stdout

        '''
        if self.socket is None:
            self.init_socket()

        self.logger.debug('Bound to %s:%s, joined group %s on interface %s (%s)' % \
                          (self.socket.getsockname()[0], MCAST_PORT, MCAST_GRP, self.interface, self.interfaceaddress))

        self.print_conns_columns()

        starttime = time.time()
        numpackets = 0
        numconnections = 0

        try:
            while True:
                self.recvbuffer = self.socket.recv(4096)

                while True:
                    if len(self.recvbuffer) >= IP_VS_CONN_HDRLEN:
                        header = SyncConnectionHeader(self.logger, socket_buffer=self.recvbuffer[0:IP_VS_CONN_HDRLEN])

                        if len(self.recvbuffer) >= header.size:
                            connections = self.decode_conns(self.recvbuffer[IP_VS_CONN_HDRLEN:header.size])

                            numpackets += 1
                            numconnections += len(connections)

                            for connection in connections:
                                print '%s %s' % (header, connection)

                            self.recvbuffer = self.recvbuffer[header.size:]
                        else:
                            break
                    else:
                        break

        except KeyboardInterrupt:
            duration = time.time() - starttime
            pass

        print 'Received %s packets (%s total connections) during %.2f seconds' % (numpackets, numconnections, duration)

        self.shut_socket()

    def print_conns_columns(self):
        header = '%s%s%s%s%s%s%s%s' % (string.ljust('syncid', 7), string.center('pro', 4), string.center('expire', 7), \
                                                string.center('state', 13), string.center('source', 22), \
                                                string.center('virtual', 22), string.center('destination', 22), 'flags')
        print header
        print (len(header) + 20) * '='

    def get_ipaddr(self, interface):
        '''
        Return the associated ip address from interface

        interface   str     'eth0'
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(\
            fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack('256s', interface[:15])) \
            [20:24])
        s.close()

    def init_socket(self):
        '''
        Initialize the multicast socket
        '''
        # Determine which interface to use
        if self.interface == None:
            self.interfaceaddress = '0.0.0.0'
        else:
            self.interfaceaddress = self.get_ipaddr(self.interface)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        # Set options
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MCAST_GRP_TTL)

        self.socket.bind(('', MCAST_PORT))

        mreq = struct.pack('4s4s', socket.inet_aton(MCAST_GRP), socket.inet_aton(self.interfaceaddress))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    def shut_socket(self):
        '''
        '''
        self.socket.close()
        self.socket = None

    def decode_conns(self, rawconns):
        '''
        Decode the binary encoded connection list, and return a list
        of dict
        '''
        conns = []
        while True:
            if len(rawconns) <= 0:
                break
            else:
                this_connection = SyncConnection(self.logger, self.name_resolution, socket_buffer=rawconns[:IP_VS_CONN_CONNLEN])
                conns.append(this_connection)

                # Shift the buffer
                rawconns = rawconns[this_connection.size:]

        return conns

    def encode_connlist(self, connlist):
        '''
        '''
        buffer = ''

        for c in connlist:
            # Conn header
            conn_type = 0
            protocol = c['protocol']
            conn_ver = 0
            conn_size = struct.calcsize('BBHIHHHHIIIII')

            ver_size = (socket.htons(conn_ver) << 12) | socket.htons(conn_size)

            # Conn data
            flags = socket.htonl(IP_VS_F_FWD_METHOD.index(c['director_type']) | self.encode_flags([IP_VS_CONN_F_NOOUTPUT['flag']]))
            state = socket.htons(IP_VS_TCP_S_CONNECTION_STATES.index('ESTABLISHED'))
            cport = socket.htons(c['cport'])
            vport = socket.htons(c['vport'])
            dport = socket.htons(c['dport'])
            fwmark = 0
            timeout = socket.htonl(c['timeout'])
            caddr = socket.htonl(self.ip_to_unsigned_int(c['caddr']))
            vaddr = socket.htonl(self.ip_to_unsigned_int(c['vaddr']))
            daddr = socket.htonl(self.ip_to_unsigned_int(c['daddr']))

            buffer += struct.pack('BBHIHHHHIIIII', conn_type, protocol, ver_size, flags, state, cport, vport, dport, fwmark, timeout, caddr, vaddr, daddr)

        return buffer

    def print_conns(self, fd, header, conns, printdate=False, nameresolution=False):
        '''
        '''
        stringlist = []

        for c in conns:
            print c

#     def print_conns_col(self, fd, printdate=False):
#         '''
#         '''
#         strformat = '%s%s%s%s%s%s%s%s' % (string.ljust('syncid', 7), string.center('pro', 4), string.center('expire', 7), \
#                                                 string.center('state', 13), string.center('source', 22), \
#                                                 string.center('virtual', 22), string.center('destination', 22), 'flags')
#         sep = (len(strformat) + 20) * '='
#
#         self.print_debug(fd, [strformat, sep], printdate)
#
#     def print_debug(self, fd, stringlist, printdate=False):
#         '''
#         '''
#         if printdate:
#             datestring = time.strftime(LVSSYNC_DEBUG_TIME_FMT) + '   '
#         else:
#             datestring = ''
#
#         for s in stringlist:
#             print >> fd, '%s%s' % (datestring, s)

# if __name__ == '__main__':
#     import socket
#     import lvssync
#     import os
#
#     if 'LVSSYNCMODE' in os.environ:
#         mode = os.environ['LVSSYNCMODE']
#     else:
#         mode = 'debug'
#
#     if 'LVSSYNCNR' in os.environ:
#         nameresolution = os.environ['LVSSYNCNR']
#     else:
#         nameresolution = False
#
#     if 'LVSSYNCINT' in os.environ:
#         sync = lvssync.ipvssync(10,os.environ['LVSSYNCINT'])
#     else:
#         sync = lvssync.ipvssync(10)
#
#     if mode == 'debug':
#         sync.debug(0,nameresolution=nameresolution,printdate=True)
#     elif mode == 'testsend':
#         connection1 = {  'protocol' : socket.SOL_TCP, 'director_type' : 'DROUTE', 'timeout' : 60, \
#                         'cport'    : 11111, 'vport' : 22222, 'dport' : 33333, \
#                         'caddr'    : '10.1.1.1', 'vaddr' : '10.2.2.2', 'daddr' : '10.3.3.3' }
#
#         connection2 = {  'protocol' : socket.SOL_TCP, 'director_type' : 'DROUTE', 'timeout' : 60, \
#                         'cport'    : 11111, 'vport' : 22222, 'dport' : 33333, \
#                         'caddr'    : '10.10.1.1', 'vaddr' : '10.20.2.2', 'daddr' : '10.30.3.3' }
#
#         connection3 = {  'protocol' : socket.SOL_TCP, 'director_type' : 'DROUTE', 'timeout' : 60, \
#                         'cport'    : 11111, 'vport' : 22222, 'dport' : 33333, \
#                         'caddr'    : '10.10.10.1', 'vaddr' : '10.20.20.2', 'daddr' : '10.30.30.3' }
#
#         conn_list = [connection1,connection2,connection3]
#         connspersec = 1
#         before = time.time()
#
#         duration = sync.get_send_conn_list_duration(conn_list,connspersec)
#
#         print 'Sending %s connections should take around %s sec at %s connections/sec' % (len(conn_list),duration,connspersec)
#         sync.send_conn_list(conn_list, connspersec=connspersec)
#
#         after = time.time()
#         print '... Sending time was %3.2f sec' % (after - before)
#
#     elif mode == 'help':
#         help(lvssync)
#
