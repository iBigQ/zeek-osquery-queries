#! Logs mounts activity.

module osquery::logging::table_mounts;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		t: time &log;
		host: string &log;
		device: string &log;
		device_alias: string &log;
		path: string &log;
		typ: string &log;
		blocks_size: int &log;
		blocks: int &log;
		flags: string &log;
	};
}

event osquery::mount_added(t: time, host_id: string, device: string, device_alias: string, path: string, typ: string, blocks_size: int, blocks: int, flags: string) {
	local info: Info = [
		 $t=t,
		 $host=host_id,
                 $device = device,
                      $device_alias = device_alias,
                      $path = path,
                      $typ = typ,
                      $blocks_size = blocks_size,
                      $blocks = blocks,
                      $flags = flags
			               ];
	
	Log::write(LOG, info);
}

event bro_init() {
	Log::create_stream(LOG, [$columns=Info, $path="osq-mounts"]);
}
