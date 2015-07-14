/* User-configurable settings.
 */

#include "config.hh"

static const char* kDefaultRsslPort = "14002";

anaguma::config_t::config_t() :
/* default values */
	service_name ("NOCACHE_VTA"),
	rssl_default_port ("24002"),
	session_name ("SessionName"),
	monitor_name ("ApplicationLoggerMonitorName"),
	event_queue_name ("EventQueueName"),
	connection_name ("ConnectionName"),
	publisher_name ("PublisherName"),
	vendor_name ("VendorName"),
	maximum_data_size (64 * 1024),
	session_capacity (2),
	worker_count (2)
{
/* C++11 initializer lists not supported in MSVC2010 */
}

/* eof */
