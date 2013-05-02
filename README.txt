===
LVS
===

[lvs]
# Plugin to display Linux Virtual Server information, 
# and a client table synchronization for out-of-synch 
# lvs load balancers.

# LVS sync identifier for manual cluster synchronization
sync-id = 0

# Specify interface to send multicast messages for
# synchronisation
sync-interface = eth0

## show loadbalancer server (show server bind)

## show loadbalancer server virtualserver (shows only virtual server, config, etc)
## show loadbalancer server virtualserver <virtualserver> connections

## show loadbalancer server realserver (shows a real server centric view)
## show loadbalancer server realserver <realserver> connections

## show loadbalancer server connections

## show cluster loadbalancer server connections
## show cluster loadbalancer server connections out-of-sync
## show cluster loadbalancer server virtualserver <virtualserver> connections
## show cluster loadbalancer server realserver <realserver> connections
