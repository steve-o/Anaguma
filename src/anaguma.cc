/* RFA interactive fake snapshot provider.
 */

#include "anaguma.hh"

#define __STDC_FORMAT_MACROS
#include <cstdint>
#include <inttypes.h>

#include <windows.h>

#include "chromium/logging.hh"
#include "error.hh"
#include "rfa_logging.hh"
#include "rfaostream.hh"

using rfa::common::RFA_String;

static std::weak_ptr<rfa::common::EventQueue> g_event_queue;

anaguma::anaguma_t::anaguma_t()
{
}

anaguma::anaguma_t::~anaguma_t()
{
	LOG(INFO) << "fin.";
}

int
anaguma::anaguma_t::Run ()
{
	LOG(INFO) << config_;

	try {
/* RFA context. */
		rfa_.reset (new rfa_t (config_));
		if (!(bool)rfa_ || !rfa_->Init())
			goto cleanup;

/* RFA asynchronous event queue. */
		const RFA_String eventQueueName (config_.event_queue_name.c_str(), 0, false);
		event_queue_.reset (rfa::common::EventQueue::create (eventQueueName), std::mem_fun (&rfa::common::EventQueue::destroy));
		if (!(bool)event_queue_)
			goto cleanup;
/* Create weak pointer to handle application shutdown. */
		g_event_queue = event_queue_;

/* RFA logging. */
		log_.reset (new logging::LogEventProvider (config_, event_queue_));
		if (!(bool)log_ || !log_->Register())
			goto cleanup;

/* RFA provider. */
		provider_.reset (new provider_t (config_, rfa_, event_queue_));
		if (!(bool)provider_ || !provider_->Init())
			goto cleanup;

	} catch (const rfa::common::InvalidUsageException& e) {
		LOG(ERROR) << "InvalidUsageException: { "
			  "\"Severity\": \"" << severity_string (e.getSeverity()) << "\""
			", \"Classification\": \"" << classification_string (e.getClassification()) << "\""
			", \"StatusText\": \"" << e.getStatus().getStatusText() << "\" }";
		goto cleanup;
	} catch (const rfa::common::InvalidConfigurationException& e) {
		LOG(ERROR) << "InvalidConfigurationException: { "
			  "\"Severity\": \"" << severity_string (e.getSeverity()) << "\""
			", \"Classification\": \"" << classification_string (e.getClassification()) << "\""
			", \"StatusText\": \"" << e.getStatus().getStatusText() << "\""
			", \"ParameterName\": \"" << e.getParameterName() << "\""
			", \"ParameterValue\": \"" << e.getParameterValue() << "\" }";
		goto cleanup;
	}

	LOG(INFO) << "Init complete, entering main loop.";
	MainLoop ();
	LOG(INFO) << "Main loop terminated, cleaning up.";
	Clear();
	return EXIT_SUCCESS;
cleanup:
	LOG(INFO) << "Init failed, cleaning up.";
	Clear();
	return EXIT_FAILURE;
}

/* On a shutdown event set a global flag and force the event queue
 * to catch the event by submitting a log event.
 */
static
BOOL
CtrlHandler (
	DWORD	fdwCtrlType
	)
{
	const char* message;
	switch (fdwCtrlType) {
	case CTRL_C_EVENT:
		message = "Caught ctrl-c event, shutting down";
		break;
	case CTRL_CLOSE_EVENT:
		message = "Caught close event, shutting down";
		break;
	case CTRL_BREAK_EVENT:
		message = "Caught ctrl-break event, shutting down";
		break;
	case CTRL_LOGOFF_EVENT:
		message = "Caught logoff event, shutting down";
		break;
	case CTRL_SHUTDOWN_EVENT:
	default:
		message = "Caught shutdown event, shutting down";
		break;
	}
/* if available, deactivate global event queue pointer to break running loop. */
	if (!g_event_queue.expired()) {
		auto sp = g_event_queue.lock();
		sp->deactivate();
	}
	LOG(INFO) << message;
	return TRUE;
}

void
anaguma::anaguma_t::MainLoop()
{
/* Add shutdown handler. */
	::SetConsoleCtrlHandler ((PHANDLER_ROUTINE)::CtrlHandler, TRUE);
	while (event_queue_->isActive()) {
		event_queue_->dispatch (rfa::common::Dispatchable::InfiniteWait);
	}
/* Remove shutdown handler. */
	::SetConsoleCtrlHandler ((PHANDLER_ROUTINE)::CtrlHandler, FALSE);
}

void
anaguma::anaguma_t::Clear()
{
/* Signal message pump thread to exit. */
	if ((bool)event_queue_) {
		event_queue_->deactivate();
	}

/* Shutdown final connecting 0mq users before bringing down bound sockets. */
	CHECK (provider_.use_count() <= 1);
	provider_.reset();
/* Release everything with an RFA dependency. */
	CHECK (log_.use_count() <= 1);
	log_.reset();
	CHECK (event_queue_.use_count() <= 1);
	event_queue_.reset();
	CHECK (rfa_.use_count() <= 1);
	rfa_.reset();
}

/* eof */