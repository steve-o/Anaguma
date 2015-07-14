/* User-configurable settings.
 *
 * NB: all strings are locale bound, RFA provides no Unicode support.
 */

#ifndef __CONFIG_HH__
#define __CONFIG_HH__
#pragma once

#include <string>
#include <sstream>
#include <vector>

namespace anaguma
{

	struct config_t
	{
		config_t();

//  Windows registry key path.
		std::string key;

//  TREP-RT service name, e.g. IDN_RDF.
		std::string service_name;

//  Default TREP-RT RSSL port, e.g. 14002, 14003.
		std::string rssl_default_port;

//  RFA session name.
		std::string session_name;

//  RFA application logger monitor name.
		std::string monitor_name;

//  RFA event queue name.
		std::string event_queue_name;

//  RFA connection name.
		std::string connection_name;

//  RFA publisher name.
		std::string publisher_name;

//  RFA vendor name.
		std::string vendor_name;

//  RFA maximum data buffer size for SingleWriteIterator.
		size_t maximum_data_size;

//  Client session capacity.
		size_t session_capacity;

//  Count of request worker threads.
		size_t worker_count;
	};

	inline
	std::ostream& operator<< (std::ostream& o, const config_t& config) {
		std::ostringstream ss;
		o << "config_t: { "
			 " \"service_name\": \"" << config.service_name << "\""
			", \"rssl_default_port\": \"" << config.rssl_default_port << "\""
			", \"session_name\": \"" << config.session_name << "\""
			", \"monitor_name\": \"" << config.monitor_name << "\""
			", \"event_queue_name\": \"" << config.event_queue_name << "\""
			", \"connection_name\": \"" << config.connection_name << "\""
			", \"publisher_name\": \"" << config.publisher_name << "\""
			", \"vendor_name\": \"" << config.vendor_name << "\""
			", \"maximum_data_size\": " << config.maximum_data_size <<
			", \"session_capacity\": " << config.session_capacity << 
			", \"worker_count\": " << config.worker_count << 
			" }";
		return o;
	}

} /* namespace anaguma */

#endif /* __CONFIG_HH__ */

/* eof */