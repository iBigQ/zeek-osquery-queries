#! Logs socket events activity

@load zeek-osquery-framework

module osquery;

export {
	## Event to indicate that a new socket connection was created on a host
	##
	## <params missing>
	global socket_event_added: event(t: time, host_id: string, action: string, pid: int, fd: int, path: string, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int, start_time: int, success: int);
}

event osquery::table_socket_events(resultInfo: osquery::ResultInfo,
action: string, pid: int, fd_str: string, path: string, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int, start_time: int, success: int) {
	local fd = to_int(fd_str);
        if (resultInfo$utype == osquery::ADD) {
		event osquery::socket_event_added(network_time(), resultInfo$host, action, pid, fd, path, family, protocol, local_address, remote_address, local_port, remote_port, start_time, success);
	}
}

event bro_init()
        {
        local query = [$ev=osquery::table_socket_events,$query="SELECT action, pid, fd, path, family, protocol, local_address, remote_address, local_port, remote_port, time, success FROM socket_events WHERE family=2", $utype=osquery::ADD];
        osquery::subscribe(query);
        }
