@load base/frameworks/cluster

@load ./main

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
@load ./tables/mounts
@load ./tables/processes
@load ./tables/process_open_sockets
@load ./tables/listening_ports
@load ./tables/users
@load ./tables/interfaces
@load ./tables/process_events
@load ./tables/socket_events
@endif

@load ./tables/mounts_log
@load ./tables/processes_log
@load ./tables/process_open_sockets_log
@load ./tables/listening_ports_log
@load ./tables/users_log
@load ./tables/interfaces_log
@load ./tables/process_events_log
@load ./tables/socket_events_log
