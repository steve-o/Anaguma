/* User-configurable settings.
 *
 * NB: all strings are locale bound, UPA provides no Unicode support.
 */

#ifndef CONFIG_HH_
#define CONFIG_HH_

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

//  TREP-RT service name, e.g. IDN_RDF, hEDD, ELEKTRON_DD.
		std::string service_name;

//  Default TREP-RT RSSL port, e.g. 14002, 14003.
		std::string rssl_default_port;

//  RSSL vendor name.
		std::string vendor_name;

//  RSSL (soft) maximum fragment size.
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
			  "\"service_name\": \"" << config.service_name << "\""
			", \"rssl_default_port\": \"" << config.rssl_default_port << "\""
			", \"vendor_name\": \"" << config.vendor_name << "\""
			", \"maximum_data_size\": " << config.maximum_data_size <<
			", \"session_capacity\": " << config.session_capacity << 
			", \"worker_count\": " << config.worker_count << 
			" }";
		return o;
	}

} /* namespace anaguma */

#endif /* CONFIG_HH_ */

/* eof */