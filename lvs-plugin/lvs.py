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

        ret, out = sysadmintoolkit.utils.get_status_output('which ipvsadm')
        if ret is not 0:
            raise sysadmintoolkit.exception.PluginError('Critical error in lvs plugin: ipvsadm command could not be found', errno=201)

        ret, out = sysadmintoolkit.utils.get_status_output('ipvsadm -L --daemon')
        if out is not '':
            self.syncid = out.splitlines()[0].split('syncid=')[-1].split(')')[0]
            self.sync_int = out.splitlines()[0].split('mcast=')[-1].split(',')[0]
        else:
            self.syncid = None
            self.sync_int = None

        self.name_resolution = config['name-resolution'].lower() in ['yes']

        self.virtual_servers = {}
        self.real_servers = {}

        self.refresh_vs_and_rs_cache()

        self.add_command(sysadmintoolkit.command.ExecCommand('debug lvs', self, self.debug))
        self.add_command(sysadmintoolkit.command.ExecCommand('show loadbalancer lvs binding', self, self.display_all_virtual_servers))

    def refresh_vs_and_rs_cache(self):
        self.logger.debug('Refreshing vistual/real server cache')
        self.virtual_servers = {}
        self.real_servers = {}

        for virtual_server_config in sysadmintoolkit.utils.get_status_output('ipvsadm -S -n | grep ^-A')[1].splitlines():
            vs = VirtualService(virtual_server_config)

            if vs.l3_addr not in self.virtual_servers:
                self.virtual_servers[vs.l3_addr] = {'services': {}, 'l3_addr': vs.l3_addr}

            self.logger.debug('Adding virtual service %s to the cache' % str(vs).upper())

            self.virtual_servers[vs.l3_addr]['services']['%s:%s' % (vs.l4_port, vs.l4_proto)] = vs

        for real_server_config in sysadmintoolkit.utils.get_status_output('ipvsadm -S -n | grep ^-a')[1].splitlines():
            rs = RealService(real_server_config)

            if rs.l3_addr not in self.real_servers:
                self.real_servers[rs.l3_addr] = {'services': {}, 'l3_addr': rs.l3_addr}

            rs.set_vs(self.virtual_servers[rs.vs_l3_addr]['services']['%s:%s' % (rs.vs_l4_port, rs.l4_proto)])
            self.virtual_servers[rs.vs_l3_addr]['services']['%s:%s' % (rs.vs_l4_port, rs.l4_proto)].add_rs(rs)

            self.logger.debug('Adding real service %s to the cache' % str(rs).upper())

            self.real_servers[rs.l3_addr]['services']['%s:%s' % (rs.l4_port, rs.l4_proto)] = rs

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

    # Sysadmin-toolkit commands

    def display_all_virtual_servers(self, line, mode):
        '''
        Displays virtual servers to real servers mapping
        '''
        virtual_servers_keys = self.virtual_servers.keys()
        virtual_servers_keys.sort()

        for virtual_server in virtual_servers_keys:
            # Skip if the name of the VS has a dot, which means it's an IPV4 address
            if self.name_resolution and '.' not in virtual_server:
                self.print_virtual_server_mapping(virtual_server)

    def display_virtual_server(self, line, mode):
        '''
        Displays Virtual Server information
        '''
        print '  displaying virtual server information'
        print

    def debug(self, line, mode):
        '''
        Displays LVS configuration and state
        '''
        print 'LVS plugin configuration and state:'
        print
        print '  LVS plugin version: %s' % __version__
        print '  ipvsadm version: %s' % sysadmintoolkit.utils.get_status_output('ipvsadm -v')[1]
        print
        print '  Name resolution: %s' % self.name_resolution
        print '  Clustering support: %s' % ('clustering' in self.plugin_set.get_plugins())
        print

        if self.syncid:
            print '  Connection synchronization information:'
            print '    syncid: %s' % self.syncid
            print '    mcast interface: %s' % self.sync_int
        else:
            print '  No connection synchronization support'
        print

# ----- LVS plugin classes -----

l4_proto_map = {'-t':'tcp', '-u':'udp', '-f':'fwmark'}
packet_forwarding_method = {'-m': 'MASQ', '-g': 'DROUTE', '-i': 'TUNNEL'}

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
LVSSYNC_DEBUG_TIME_FMT = '%c'  # To prefix debugging entries

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

    examples:
    $ LVSSYNCMODE=testsend LVSSYNCINT=eth0 python lvssync.py
    Sending 3 connections should take around 2 sec at 1 connections/sec
    ... Sending time was 2.00 sec

    $ LVSSYNCINT=eth0 python lvssync.py
    Bound to 0.0.0.0:8848, joined group 224.0.0.81 on interface eth0 (192.168.1.1)
    syncid pro  expire    state            source               virtual             destination      flags
    ==========================================================================================================================
    0      TCP    1:40 ESTABLISHED     10.1.1.1:11111        10.2.2.2:22222        10.3.3.3:33333    DROUTE NOOUTPUT
    0      TCP    1:40 ESTABLISHED     10.1.1.1:11111        10.2.2.2:22222        10.3.3.3:33333    DROUTE NOOUTPUT
    0      TCP    1:40 ESTABLISHED     10.1.1.1:11111        10.2.2.2:22222        10.3.3.3:33333    DROUTE NOOUTPUT

    Reference for packet structure:
    http://lxr.free-electrons.com/source/net/netfilter/ipvs/ip_vs_sync.c

    Author: Louis-Philippe Theriault (lpther@gmail.com)
    '''

    def __init__(self, syncid, interface=None):
        '''
        Main class to receive or send ipvs sync connections
        Supports only Version 1 ip_vs_sync connections

        interface   str     interface to bind the mcast socket
                            defaults to socket.INADDR_ANY
        syncid      int     syncid instance identifier
        '''
        self.interface = interface
        self.interfaceaddress = None
        self.interfacemtu = 1500
        self.maxmcastmessage = self.interfacemtu - 68  # Safe header room for IP + UDP
        self.syncid = syncid
        self.socket = None
        self.socketisblocking = None
        self.recvbuffer = ''
        self.sendbuffer = ''

    def getsendconnlistduration(self, connlist, connspersec=250):
        '''
        Returns the number of seconds if should take to send this list of connections
        '''
        maxconnpermessage = int(math.floor((self.maxmcastmessage - IP_VS_CONN_HDRLEN) / IP_VS_CONN_CONNLEN))
        maxconnpermessage = min(maxconnpermessage, connspersec)

        return int(math.ceil(float(len(connlist)) / connspersec)) - 1

    def sendconnlist(self, connlist, connspersec=250):
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
            self.__initsocket()

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
                buffconns = self.__encode_connlist(connlist[:nr_conns])

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

        self.__shutsocket()


    def debug(self, duration, fd=sys.stdout, printdate=False, nameresolution=False):
        '''
        Binds to the ipvs sync multicast address and dumps received packets
        to the fd during the specified time.

        duration    int      seconds
        '''
        if self.socket == None:
            self.__initsocket(blocking=False)

        self.__print_debug(fd, ['Bound to %s:%s, joined group %s on interface %s (%s)' % \
            (self.socket.getsockname()[0], MCAST_PORT, MCAST_GRP, self.interface, self.interfaceaddress)], printdate)

        self.__print_conns_col(fd, printdate)

        starttime = time.time()
        numpackets = 0
        numconnections = 0
        try:
            while True:
                while True:
                    try:
                        newbuffer = self.socket.recv(9999)
                    except socket.error as e:
                        if e.errno == 11:
                            newbuffer = ''
                        else:
                            raise

                    if len(newbuffer) > 0:
                        self.recvbuffer += newbuffer
                    else:
                        break

                while True:
                    if len(self.recvbuffer) >= IP_VS_CONN_HDRLEN:
                        reserved , syncid , rawsize , nr_conns, version, spare = struct.unpack('BBHBbH', self.recvbuffer[0:IP_VS_CONN_HDRLEN])

                        # Network to host conversions
                        size = socket.ntohs(rawsize)

                        header = {}
                        header['reserved'] = reserved
                        header['syncid'] = syncid
                        header['size'] = size
                        header['nr_conns'] = nr_conns
                        header['version'] = version
                        header['spare'] = spare

                        if len(self.recvbuffer) >= size:
                            conns = self.__decode_conns(self.recvbuffer[IP_VS_CONN_HDRLEN:header['size']])

                            numpackets += 1
                            numconnections += len(conns)

                            self.__print_conns(fd, header, conns, nameresolution=nameresolution, printdate=printdate)

                            self.recvbuffer = self.recvbuffer[header['size']:]
                        else:
                            break
                    else:
                        break

                if duration == 0 or time.time() - starttime < duration:
                    time.sleep(LVSSYNC_MIN_SLEEP)
                else:
                    break
        except KeyboardInterrupt:
            duration = time.time() - starttime
            pass

        print >> fd, 'Received %s packets (%s total connections) during %.2f seconds' % (numpackets, numconnections, duration)

        self.__shutsocket()

    def __getipaddr(self, interface):
        '''
        Return the associated ip address from interface

        interface   str     'eth0'
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(\
            fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack('256s', interface[:15])) \
            [20:24])
        s.close()

    def __initsocket(self, blocking=True):
        '''
        Initialize the multicast socket
        '''
        # Determine which interface to use
        if self.interface == None:
            self.interfaceaddress = '0.0.0.0'
        else:
            self.interfaceaddress = self.__getipaddr(self.interface)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socketisblocking = blocking

        # Set options
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MCAST_GRP_TTL)

        self.socket.bind(('', MCAST_PORT))

        mreq = struct.pack('4s4s', socket.inet_aton(MCAST_GRP), socket.inet_aton(self.interfaceaddress))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        if not blocking:
            self.socket.setblocking(0)

    def __shutsocket(self):
        '''
        '''
        self.socket.close()
        self.socket = None
        self.socketisblocking = None

    def __decode_conns(self, rawconns):
        '''
        Decode the binary encoded connection list, and return a list
        of dict
        '''
        conns = []
        while True:
            if len(rawconns) <= 0:
                break
            else:
                conn_type, protocol, ver_size, flags, state, cport, \
                vport, dport, fwmark, timeout, caddr, vaddr, daddr = struct.unpack('BBHIHHHHIIIII', rawconns[:IP_VS_CONN_CONNLEN])

                conn_size = socket.ntohs(ver_size) & 0b0000111111111111
                conn_ver = socket.ntohs(ver_size) >> 12

                this_conn = {}
                this_conn['type'] = conn_type
                this_conn['protocol'] = protocol
                this_conn['version'] = conn_ver
                this_conn['size'] = conn_size
                this_conn['flags'] = self.__decode_flags(socket.ntohl(flags))
                this_conn['state'] = IP_VS_TCP_S_CONNECTION_STATES[socket.ntohs(state)]
                this_conn['cport'] = socket.ntohs(cport)
                this_conn['vport'] = socket.ntohs(vport)
                this_conn['dport'] = socket.ntohs(dport)
                this_conn['timeout'] = int(socket.ntohl(timeout))
                this_conn['caddr'] = self.__unsigned_int_to_ip(socket.ntohl(caddr))
                this_conn['vaddr'] = self.__unsigned_int_to_ip(socket.ntohl(vaddr))
                this_conn['daddr'] = self.__unsigned_int_to_ip(socket.ntohl(daddr))

                conns.append(this_conn)

                # Shift the buffer
                rawconns = rawconns[conn_size:]

        return conns

    def __encode_connlist(self, connlist):
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
            flags = socket.htonl(IP_VS_F_FWD_METHOD.index(c['director_type']) | self.__encode_flags([IP_VS_CONN_F_NOOUTPUT['flag']]))
            state = socket.htons(IP_VS_TCP_S_CONNECTION_STATES.index('ESTABLISHED'))
            cport = socket.htons(c['cport'])
            vport = socket.htons(c['vport'])
            dport = socket.htons(c['dport'])
            fwmark = 0
            timeout = socket.htonl(c['timeout'])
            caddr = socket.htonl(self.__ip_to_unsigned_int(c['caddr']))
            vaddr = socket.htonl(self.__ip_to_unsigned_int(c['vaddr']))
            daddr = socket.htonl(self.__ip_to_unsigned_int(c['daddr']))

            buffer += struct.pack('BBHIHHHHIIIII', conn_type, protocol, ver_size, flags, state, cport, vport, dport, fwmark, timeout, caddr, vaddr, daddr)

        return buffer

    def __decode_flags(self, rawflags):
        '''
        '''
        flags = []

        flags += [ IP_VS_F_FWD_METHOD[rawflags & 0x0007] ]

        for f in IP_VS_F_BOOL:
            if rawflags & f['flag']:
                flags.append(f['flagname'])

        return flags

    def __encode_flags(self, flagslist):
        '''
        '''
        rawflags = 0x0000

        for f in flagslist:
            rawflags = rawflags | f

        return rawflags

    def __unsigned_int_to_ip(self, unsigned_int):
        '''
        Return dotted quad ip str
        '''
        a = (unsigned_int & 0xff000000) >> 24
        b = (unsigned_int & 0x00ff0000) >> 16
        c = (unsigned_int & 0x0000ff00) >> 8
        d = unsigned_int & 0x000000ff
        return '%s.%s.%s.%s' % (a, b, c, d)

    def __ip_to_unsigned_int(self, dotted_quad_ip):
        '''
        Return unsigned int from dotted quad
        '''
        unsigned_int = 0x00000000
        for quad_id in range(4):
            quad = dotted_quad_ip.split('.')[quad_id]

            unsigned_int += int(quad) << ((8 * (3 - quad_id)))

        return unsigned_int

    def __print_conns(self, fd, header, conns, printdate=False, nameresolution=False):
        '''
        '''
        stringlist = []

        for c in conns:
            # Get protocol name
            if c['protocol'] == socket.SOL_TCP:
                protocol_str = 'TCP'
            elif c['protocol'] == socket.SOL_UDP:
                protocol_str = 'UDP'
            else:
                protocol_str = str(c['protocol'])

            # Get expiration format
            expire = '%3d:%2s' % (c['timeout'] / 60, str(c['timeout'] % 60).zfill(2))

            # Get s/v/d client:protocol pair
            caddr, vaddr , daddr = (c['caddr'] , c['vaddr'] , c['daddr'])
            addrspacer = ''

            if nameresolution:
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


            source = '%s:%s' % (caddr, c['cport']) + addrspacer
            virtual = '%s:%s' % (vaddr, c['vport']) + addrspacer
            destination = '%s:%s' % (daddr, c['dport']) + addrspacer

            strformat = '%s%s%s%s%s%s%s%s' % (string.ljust(str(header['syncid']), 7), string.center(protocol_str, 4), string.center(expire, 7), \
                                                    string.center(c['state'], 13), string.center(source, 22), \
                                                    string.center(virtual, 22), string.center(destination, 22), ' '.join(c['flags']))

            stringlist += [strformat]

        self.__print_debug(fd, stringlist, printdate)

    def __print_conns_col(self, fd, printdate=False):
        '''
        '''
        strformat = '%s%s%s%s%s%s%s%s' % (string.ljust('syncid', 7), string.center('pro', 4), string.center('expire', 7), \
                                                string.center('state', 13), string.center('source', 22), \
                                                string.center('virtual', 22), string.center('destination', 22), 'flags')
        sep = (len(strformat) + 20) * '='

        self.__print_debug(fd, [strformat, sep], printdate)

    def __print_debug(self, fd, stringlist, printdate=False):
        '''
        '''
        if printdate:
            datestring = time.strftime(LVSSYNC_DEBUG_TIME_FMT) + '   '
        else:
            datestring = ''

        for s in stringlist:
            print >> fd, '%s%s' % (datestring, s)

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
#         duration = sync.getsendconnlistduration(conn_list,connspersec)
#
#         print 'Sending %s connections should take around %s sec at %s connections/sec' % (len(conn_list),duration,connspersec)
#         sync.sendconnlist(conn_list, connspersec=connspersec)
#
#         after = time.time()
#         print '... Sending time was %3.2f sec' % (after - before)
#
#     elif mode == 'help':
#         help(lvssync)
#
