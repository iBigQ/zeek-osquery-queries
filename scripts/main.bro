module osquery;

export {
	# Interval in seconds to execute scheduled queries on hosts
	global QUERY_INTERVAL: count = 2 &redef;
}
