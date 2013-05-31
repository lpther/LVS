# LVS Plugin #

A Sysadmin-Toolkit Plugin that can sort and display LVS cluster connections, and can launch an on-demand synchronization of the connection table when it is out-of-sync between nodes of the cluster.

## Plugin Description ##

The plugin uses /proc/net/ipvs_* and ipvsadm, and sorts this information for a virtual or real server centric view.

The connection synchronization uses the Clustering plugin, and generates multicast packets that are received by the sync daemon and updates all LVS in the cluster with missing connections.

## Installation ##

Clustering Plugin is coded for python 2.7 on Ubuntu 12.04, and requires the following packages:

- Sysadmin-Toolkit ([https://github.com/lpther/SysadminToolkit](https://github.com/lpther/SysadminToolkit))
- Clustering plugin for lvssync feature ([https://github.com/lpther/Clustering](https://github.com/lpther/Clustering "https://github.com/lpther/Clustering"))

## Basic Usage ##

The plugin adds 3 views to the LVS configuration.

Virtual to Real Server mapping:

	sysadmin-toolkit(root)# show loadbalancer lvs binding
	    ldap (10.10.10.100):
	
	              ldap/389/tcp    lc ->         ldap4/   10.10.10.201:389   droute  active weight:250
	                                 ->         ldap5/   10.10.10.202:389   droute  active
	
	             ldaps/636/tcp    lc ->         ldap4/   10.10.10.201:636   droute  active weight:250
	                                 ->         ldap5/   10.10.10.202:636   droute  active
	
	    ldap-op (10.10.20.100):
	
	              ldap/389/tcp    lc ->         ldap1/   10.10.20.201:389   droute  active
	                                 ->         ldap2/   10.10.20.202:389   droute  active
	
	             ldaps/636/tcp    lc ->         ldap1/   10.10.20.201:636   droute  active
	                                 ->         ldap2/   10.10.20.202:636   droute  active

Real Server View:

	sysadmin-toolkit(root)# show loadbalancer lvs real-server
	    ldap1              IP:   10.10.20.201         Total Connections: 1787
	
	              ldap/389/tcp              Virtual Server:  10.10.20.100:389    Connections: 1310
	
	                                        Weight:1      Forwarding Method: Direct Routing (Gatewaying)
	
	                                        Established: 1027
	                                           Fin-Wait: 199
	                                            Closing: 84
	
	             ldaps/636/tcp              Virtual Server:  10.10.20.100:636    Connections: 477
	
	                                        Weight:1      Forwarding Method: Direct Routing (Gatewaying)
	
	                                        Established: 288
	                                           Fin-Wait: 187
	                                            Closing: 2


Virtual Server view. Note that the __Owner__ field is available if the Clustering plugin is loaded:

	sysadmin-toolkit(root)# show loadbalancer lvs virtual-server
	    ldap               IP:   10.10.10.100    Owner: lvs-1:eth0    Total Connections: 5359
	
	              ldap/389/tcp             Scheduler: Least-Connection             Connections: 479
	
	                           Established: 179
	                              Fin-Wait: 18
	                               Closing: 282
	
	             ldaps/636/tcp             Scheduler: Least-Connection             Connections: 4880
	
	                           Established: 4443
	                              Fin-Wait: 437
	                               Closing: 0


If the clustering plugin is loaded, testing and synchronizing out-of-sync connections is available:

	sysadmin-toolkit(root)# show loadbalancer lvs connections
	IPVS connection entries
	pro expire state       source             virtual            destination
	
	sysadmin-toolkit(root)# synchronize loadbalancer lvs connections test
	Sending test client connection: 
        TCP    0:30 ESTABLISHED   10.11.11.11:11111     10.22.22.22:22222     10.33.33.33:33333   MASQ NOOUTPUT
	
	Validating all nodes received the connection...
	
	Test results:
	
	  slbcmc-1:       Success
	
	  slbcmc-2:       Success
	
	sysadmin-toolkit(root)# show loadbalancer lvs connections
	IPVS connection entries
	pro expire state       source             virtual            destination
	TCP 00:27  ESTABLISHED 10.11.11.11:11111  10.22.22.22:22222  10.33.33.33:33333
	
List the plugin's internal configuration:

	sysadmin-toolkit(root)# debug lvs
	LVS plugin configuration and state:
	
	  LVS plugin version: 0.1.0b
	  ipvsadm version: ipvsadm v1.25 2008/5/15 (compiled with popt and IPVS v1.2.1)
	
	
	  Name resolution: True
	
	  Clustering support: True
	    Nodeset: default
	      Nodes: lvs-[1-2]
	
	  Connection synchronization information:
	        sync version: 1
	              syncid: 10
	     mcast interface: eth0
	    max cps for sync: 250 connections/second


# Related Projects #

- Sysadmin-Toolkit ([https://github.com/lpther/SysadminToolkit](https://github.com/lpther/SysadminToolkit))
