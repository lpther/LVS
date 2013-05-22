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
    global plugin_instance

    if plugin_instance is None:
        plugin_instance = LVS(logger, config)

    return plugin_instance


class LVS(sysadmintoolkit.plugin.Plugin):
    def __init__(self, logger, config):
        super(LVS, self).__init__('lvs', logger, config)

        self.clustering_plugin = None

        ret, out = sysadmintoolkit.utils.get_status_output('which ipvsadm', self.logger)
        if ret is not 0:
            raise sysadmintoolkit.exception.PluginError('Critical error in lvs plugin: ipvsadm command could not be found', errno=201)

        self.name_resolution = self.config['name-resolution'].lower() in ['yes']

        self.cluster_nodeset_name = 'default'

        self.ipvssync_cps = 250
        if 'lvs-sync-cps' in self.config:
            try:
                self.ipvssync_cps = int(self.config['lvs-sync-cps'])
            except:
                self.logger.error('lvs-sync-cps must be an integer!')

        ret, out = sysadmintoolkit.utils.get_status_output('ipvsadm -L --daemon', self.logger)
        if ret is 0:
            self.syncid = int(out.splitlines()[0].split('syncid=')[-1].split(')')[0])
            self.sync_int = out.splitlines()[0].split('mcast=')[-1].split(',')[0]
            self.sync_version = int(sysadmintoolkit.utils.get_status_output('cat /proc/sys/net/ipv4/vs/sync_version', self.logger)[1].strip())
            self.ipvssync = IPVSSync(self.syncid, self.logger, self.name_resolution, interface=self.sync_int, sync_protocol_version=self.sync_version)
        else:
            self.syncid = None
            self.sync_int = None
            self.ipvssync = None

        self.virtual_servers = {}
        self.real_servers = {}

        self.add_command(sysadmintoolkit.command.ExecCommand('debug lvs', self, self.debug), modes=['root', 'config'])
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs binding', self, self.display_virtual_servers_mapping), modes=['root', 'config'])
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs virtual-server', self, self.display_virtual_server_cmd), modes=['root', 'config'])
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs virtual-server <virtual-server>', self, self.display_virtual_server_cmd), modes=['root', 'config'])
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs real-server', self, self.display_real_server_cmd), modes=['root', 'config'])
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs real-server <real-server>', self, self.display_real_server_cmd), modes=['root', 'config'])
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs connections', self, self.display_connections_cmd), modes=['root', 'config'])

        self.add_dynamic_keyword_fn('<virtual-server>', self.get_virtual_servers, modes=['root', 'config'])
        self.add_dynamic_keyword_fn('<real-server>', self.get_real_servers, modes=['root', 'config'])

        if self.syncid:
            self.add_command(sysadmintoolkit.command.ExecCommand('debug lvs lvssync', self, self.debug_lvs_sync), modes=['root', 'config'])

    def update_plugin_set(self, plugin_set):
        super(LVS, self).update_plugin_set(plugin_set)

        if 'clustering' in self.plugin_set.get_plugins():
            self.clustering_plugin = self.plugin_set.get_plugins()['clustering']

            self.add_command(sysadmintoolkit.command.ExecCommand('show cluster loadbalancer lvs connections out-of-sync', self, self.display_oos_connections_cmd), modes=['root', 'config'])
            self.add_command(sysadmintoolkit.command.ExecCommand('synchronize loadbalancer lvs connections test', self, self.test_lvssync), modes=['root'])
            self.add_command(sysadmintoolkit.command.ExecCommand('synchronize loadbalancer lvs connections', self, self.lvssync_synchronize), modes=['root'])

    def enter_mode(self, cmdprompt):
        '''
        '''
        super(LVS, self).enter_mode(cmdprompt)

        if cmdprompt.get_mode() is not 'operator':
            self.refresh_vs_and_rs_cache()

    def clear_cache(self):
        '''
        '''
        if self.cmdstack[-1].get_mode() is not 'operator':
            self.refresh_vs_and_rs_cache()

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

    def get_cluster_connections(self):
        return self.clustering_plugin.run_cluster_command('ipvsadm -L -n -c | grep -v ^IPVS | grep -v ^pro', \
                                                          self.clustering_plugin.get_reachable_nodes(self.cluster_nodeset_name))

    def get_oos_connections(self):
        buffer_nodes_list = self.get_cluster_connections()

        nodemap = {}
        all_connections = {}

        for node in self.clustering_plugin.get_reachable_nodes(self.cluster_nodeset_name):
            # Nodes that returns 0 connections must show up regardless
            nodemap[node] = {'raw_connections_list': '', 'connections_map': {}}

        for (buffer, nodes) in buffer_nodes_list:
            for node in nodes:
                connections_map = {}
                for connection in buffer.splitlines():
                    connection_without_timeout = ' '.join([connection.split()[0]] + connection.split()[2:])
                    min, sec = connection.split()[1].split(':')
                    connections_map[connection_without_timeout] = (int(min) * 60) + int(sec)

                    if connection_without_timeout not in all_connections:
                        all_connections[connection_without_timeout] = connections_map[connection_without_timeout]
                    else:
                        all_connections[connection_without_timeout] = max(all_connections[connection_without_timeout], \
                                                                          connections_map[connection_without_timeout])

                nodemap[node] = {'raw_connections_list': buffer, 'connections_map': connections_map}

        nodes = nodemap.keys()
        nodes.sort()
        for node in nodes:
            missing_connections = []

            if len(nodemap[node]['connections_map']) is not len(all_connections):
                self.logger.warning('Node %s has %s out-of sync connections' % (node, len(all_connections) - len(nodemap[node]['connections_map'])))

                for connection in all_connections:
                    if connection not in nodemap[node]['connections_map']:
                        missing_connections.append(connection)

            nodemap[node]['missing_connections_map'] = missing_connections

        return nodemap, all_connections

    def display_oos_connections(self, nodemap, all_connections):
        oos_connections_result = 0

        print 'Out-of-sync connections:'

        nodes = nodemap.keys()
        nodes.sort()
        for node in nodes:
            if len(nodemap[node]['missing_connections_map']):
                oos_connections_result = 1

            print '  %s %s' % (('%s:' % node).ljust(15), str(len(nodemap[node]['missing_connections_map'])).rjust(5))

            for connection in nodemap[node]['missing_connections_map']:
                print '    %s' % connection

            print

        return oos_connections_result

    # Dynamic keywords

    def get_virtual_servers(self, user_input_obj=None):
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

    def get_real_servers(self, user_input_obj=None):
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

    def display_connections_cmd(self, user_input_obj):
        '''
        Displays connection table
        '''
        print sysadmintoolkit.utils.get_status_output('ipvsadm -L -n -c', self.logger)[1]

    def display_oos_connections_cmd(self, user_input_obj):
        '''
        Displays out of sync connections between lvs in the cluster
        '''
        self.logger.debug('Displaying out-of-sync connections')

        nodemap, all_connections = self.get_oos_connections()

        return self.display_oos_connections(nodemap, all_connections)

    def test_lvssync(self, user_input_obj):
        '''
        Send dummy client connections to verify sync functionality
        '''
        self.logger.debug('Testing LVS Sync functionality')

        dummy_connection1 = SyncConnection(self.logger, name_resolution=self.name_resolution)
        dummy_connection1.set_caddr_cport('10.11.11.11', 11111)
        dummy_connection1.set_vaddr_vport('10.22.22.22', 22222)
        dummy_connection1.set_daddr_dport('10.33.33.33', 33333)
        dummy_connection1.set_timeout(30)

        print 'Sending test client connection: %s' % dummy_connection1
        print

        self.ipvssync.send_conn_list([dummy_connection1], self.ipvssync_cps)

        print 'Validating all nodes received the connection... '
        print

        buffer_nodes_list = self.get_cluster_connections()

        nodemap = {}

        for node in self.clustering_plugin.get_reachable_nodes(self.cluster_nodeset_name):
            # Nodes that returns 0 connections must show up regardless
            nodemap[node] = sysadmintoolkit.utils.get_red_text('Failed')

        for (buffer, nodes) in buffer_nodes_list:
            for node in nodes:
                for connection in buffer.splitlines():
                    if 'ESTABLISHED 10.11.11.11:11111  10.22.22.22:22222  10.33.33.33:33333' in connection:
                        nodemap[node] = sysadmintoolkit.utils.get_green_text('Success')
                        break

        nodemap_keys = nodemap.keys()
        nodemap_keys.sort()

        print 'Test results:'
        print

        for node in nodemap_keys:
            print '  %s %s' % (('%s:' % node).ljust(15), nodemap[node])
            print

    def lvssync_synchronize(self, user_input_obj):
        '''
        Synchronizes out-of-sync connections across the cluster
        '''
        self.logger.info('Synchronizing LVS connections across the cluster')

        nodemap, all_connections = self.get_oos_connections()

        connections_to_sync_map = {}

        for node in nodemap:
            for missing_connection in nodemap[node]['missing_connections_map']:
                if missing_connection not in connections_to_sync_map:
                    sync_connection = SyncConnection(self.logger, self.name_resolution)

                    state, caddr_port, vaddr_port, daddr_port = missing_connection.split()[1:]

                    sync_connection.set_caddr_cport(caddr_port.split(':')[0], int(caddr_port.split(':')[1]))
                    sync_connection.set_vaddr_vport(vaddr_port.split(':')[0], int(vaddr_port.split(':')[1]))
                    sync_connection.set_daddr_dport(daddr_port.split(':')[0], int(daddr_port.split(':')[1]))
                    sync_connection.set_timeout(all_connections[missing_connection])

                    connections_to_sync_map[missing_connection] = sync_connection

        connlist = [conn for k, conn in connections_to_sync_map.items()]

        self.logger.debug('Sending following connections for synchronization:')
        for connection_obj in connlist:
            self.logger.debug('  %s' % connection_obj)

        print 'Sending %s connections from interface %s to syncid %s' % (len(connlist), self.sync_int, self.syncid)
        print
        print 'Full synchronization should take %s seconds at a rate of %s connections per second' % \
                (self.ipvssync.get_send_conn_list_duration(connlist, self.ipvssync_cps), self.ipvssync_cps)
        print

        self.ipvssync.send_conn_list(connlist, self.ipvssync_cps)

        print 'Synchronization ended, validating...'
        print

        return self.display_oos_connections_cmd(None, None)

    def display_virtual_servers_mapping(self, user_input_obj):
        '''
        Displays virtual servers to real servers mapping
        '''
        self.refresh_vs_and_rs_cache()

        virtual_servers_keys = self.virtual_servers.keys()
        virtual_servers_keys.sort()

        for virtual_server in virtual_servers_keys:
            if self.name_resolution and sysadmintoolkit.utils.is_ipv4_addr(virtual_server):
                continue

            self.print_virtual_server_mapping(virtual_server)

    def display_virtual_server_cmd(self, user_input_obj):
        '''
        Displays Virtual Server information
        '''
        line = user_input_obj.get_entered_command()

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

    def display_real_server_cmd(self, user_input_obj):
        '''
        Displays Real Server information
        '''
        line = user_input_obj.get_entered_command()

        self.refresh_vs_and_rs_cache()

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


    def debug(self, user_input_obj):
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
            print '        sync version: %s' % self.sync_version
            print '              syncid: %s' % self.syncid
            print '     mcast interface: %s' % self.sync_int
            print '    max cps for sync: %s connections/second' % self.ipvssync_cps
        else:
            print '  No connection synchronization support'
        print

    def debug_lvs_sync(self, user_input_obj):
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
        self.logger = logger

        self.size = None
        self.reserved = 0
        self.syncid = 0
        self.nr_conns = 0
        self.version = 1
        self.spare = 0

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

    def encode_for_socket(self):
        return struct.pack('BBHBbH', self.reserved, self.syncid, socket.htons(self.size), self.nr_conns, self.version, self.spare)

    def set_syncid(self, syncid):
        self.syncid = syncid

    def set_nr_conns(self, nr_conns):
        self.nr_conns = nr_conns

    def set_version(self, version):
        self.version = version

    def set_size(self, size):
        self.size = size


class SyncConnection(object):
    def __init__(self, logger, name_resolution, socket_buffer=None):
        self.logger = logger
        self.name_resolution = name_resolution

        self.type = 0
        self.protocol = socket.SOL_TCP
        self.version = 0
        self.size = None
        self.flags = IP_VS_CONN_F_NOOUTPUT['flag']
        self.state = IP_VS_TCP_S_CONNECTION_STATES.index('ESTABLISHED')
        self.cport = None
        self.vport = None
        self.dport = None
        self.timeout = None
        self.caddr = None
        self.vaddr = None
        self.daddr = None
        self.fwmark = 0

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
                                                string.center(IP_VS_TCP_S_CONNECTION_STATES[self.state], 13), string.center(source, 22), \
                                                string.center(virtual, 22), string.center(destination, 22), ' '.join(self.decode_flags(self.flags)))

    def decode_from_socket(self, socket_buffer):
        conn_type, protocol, ver_size, flags, state, cport, \
        vport, dport, fwmark, timeout, caddr, vaddr, daddr = struct.unpack('BBHIHHHHIIIII', socket_buffer[:IP_VS_CONN_CONNLEN])

        self.type = conn_type
        self.protocol = protocol
        self.version = socket.ntohs(ver_size) >> 12
        self.size = socket.ntohs(ver_size) & 0b0000111111111111
        self.flags = socket.ntohl(flags)
        self.state = socket.ntohs(state)
        self.cport = socket.ntohs(cport)
        self.vport = socket.ntohs(vport)
        self.dport = socket.ntohs(dport)
        self.fwmark = int(socket.ntohl(fwmark))
        self.timeout = int(socket.ntohl(timeout))
        self.caddr = self.unsigned_int_to_ip(socket.ntohl(caddr))
        self.vaddr = self.unsigned_int_to_ip(socket.ntohl(vaddr))
        self.daddr = self.unsigned_int_to_ip(socket.ntohl(daddr))

    def encode_for_socket(self):
        # Conn header
        conn_size = struct.calcsize('BBHIHHHHIIIII')
        ver_size = (socket.htons(self.version) << 12) | socket.htons(conn_size)

        # Conn data
        state = socket.htons(IP_VS_TCP_S_CONNECTION_STATES.index('ESTABLISHED'))
        caddr = socket.htonl(self.ip_to_unsigned_int(self.caddr))
        vaddr = socket.htonl(self.ip_to_unsigned_int(self.vaddr))
        daddr = socket.htonl(self.ip_to_unsigned_int(self.daddr))

        return struct.pack('BBHIHHHHIIIII', self.type, self.protocol, ver_size, socket.htonl(self.flags), \
                              socket.htons(self.state), socket.htons(self.cport), socket.htons(self.vport), \
                              socket.htons(self.dport), socket.htonl(self.fwmark), socket.htonl(self.timeout), \
                              caddr, vaddr, daddr)


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

    def set_protocol(self, protocol):
        '''
        socket.SOL_TCP or socket.SOL_UDP

        Normally this would be TCP
        '''
        self.protocol = protocol

    def set_state(self, state):
        '''
        This is the index of IP_VS_TCP_S_CONNECTION_STATES

        ex:
            set_state(IP_VS_TCP_S_CONNECTION_STATES.index('ESTABLISHED'))
        '''
        self.state = state

    def set_flags(self, flags):
        '''
        Bitwise or of IP_VS_F flags. This is here the director type is set, and you can launch debug mode to
        see which other flags are useful.

        IP_VS_F_FWD_METHOD is a list of forwarding modes, the index is the flag

        Other flags are defined in IP_VS_CONN_F*['flag']

        Ex:
            set_flags(IP_VS_F_FWD_METHOD.index('DROUTE') | IP_VS_CONN_F_NOOUTPUT['flag'])
        '''
        self.flags = flags

    def set_caddr_cport(self, caddr, cport):
        '''
        addr is an ipv4 address, in the format "10.11.12.13"
        cport in an int representing the l4 port
        '''
        self.caddr = caddr
        self.cport = cport

    def set_vaddr_vport(self, vaddr, vport):
        '''
        addr is an ipv4 address, in the format "10.11.12.13"
        cport in an int representing the l4 port
        '''
        self.vaddr = vaddr
        self.vport = vport

    def set_daddr_dport(self, daddr, dport):
        '''
        addr is an ipv4 address, in the format "10.11.12.13"
        cport in an int representing the l4 port
        '''
        self.daddr = daddr
        self.dport = dport

    def set_timeout(self, timeout):
        self.timeout = timeout


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

        connlist    list    [SyncConnection]
        connspersec int     Upper limit of connections per second to transmit

        '''
        self.logger.info('Sending %s IPVS sync connections' % len(connlist))

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

                header = SyncConnectionHeader(self.logger)
                header.set_nr_conns(nr_conns)
                header.set_syncid(self.syncid)
                header.set_version(self.sync_protocol_version)
                header.set_size(IP_VS_CONN_HDRLEN + len(buffconns))

                self.socket.sendto(header.encode_for_socket() + buffconns, (MCAST_GRP, MCAST_PORT))

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
            buffer += c.encode_for_socket()

        return buffer

    def print_conns(self, fd, header, conns, printdate=False, nameresolution=False):
        '''
        '''
        stringlist = []

        for c in conns:
            print c

