module osquery;

@load zeek-osquery-framework

export {

	# Interval in seconds to execute scheduled queries on hosts
	global QUERY_INTERVAL: count = 10 &redef;
}
