/* RFA interactive fake snapshot provider.
 *
 * An interactive provider sits listening on a port for RSSL connections,
 * once a client is connected requests may be submitted for snapshots or
 * subscriptions to item streams.  This application will broadcast updates
 * continuously independent of client interest and the provider side will
 * perform fan-out as required.
 *
 * The provider is not required to perform last value caching, forcing the
 * client to wait for a subsequent broadcast to actually see data.
 */

#ifndef __ANAGUMA_HH__
#define __ANAGUMA_HH__
#pragma once

#include <cstdint>
#include <forward_list>
#include <memory>

/* Boost Chrono. */
#include <boost/chrono.hpp>

/* Boost noncopyable base class */
#include <boost/utility.hpp>

/* Boost threading. */
#include <boost/thread.hpp>

/* RFA 7.2 */
#include <rfa/rfa.hh>

#include "chromium/logging.hh"

#include "config.hh"
#include "provider.hh"

namespace logging
{
	class LogEventProvider;
}

namespace anaguma
{
	class rfa_t;
	class provider_t;

	class anaguma_t :
		boost::noncopyable
	{
	public:
		anaguma_t();
		~anaguma_t();

/* Run the provider with the given command-line parameters.
 * Returns the error code to be returned by main().
 */
		int Run();
		void Clear();

	private:

/* Run core event loop. */
		void MainLoop();

/* Application configuration. */
		config_t config_;

/* RFA context. */
		std::shared_ptr<rfa_t> rfa_;

/* RFA asynchronous event queue. */
		std::shared_ptr<rfa::common::EventQueue> event_queue_;

/* RFA logging */
		std::shared_ptr<logging::LogEventProvider> log_;

/* RFA provider */
		std::shared_ptr<provider_t> provider_;	
	};

} /* namespace anaguma */

#endif /* __ANAGUMA_HH__ */

/* eof */