/* UPA interactive fake snapshot provider.
 */

#include "anaguma.hh"

#define __STDC_FORMAT_MACROS
#include <cstdint>
#include <inttypes.h>

#include <windows.h>

#include "chromium/logging.hh"
#include "upa.hh"

static std::weak_ptr<anaguma::provider_t> g_provider;


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
/* UPA context. */
		upa_.reset (new upa_t (config_));
		if (!(bool)upa_ || !upa_->Init())
			goto cleanup;

/* UPA provider. */
		provider_.reset (new provider_t (config_, upa_));
		if (!(bool)provider_ || !provider_->Init())
			goto cleanup;
/* Create weak pointer to handle application shutdown. */
		g_provider = provider_;

	} catch (const std::exception& e) {
		LOG(ERROR) << "Exception: { "
			"\"What\": \"" << e.what() << "\" }";
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
		message = "Caught ctrl-c event";
		break;
	case CTRL_CLOSE_EVENT:
		message = "Caught close event";
		break;
	case CTRL_BREAK_EVENT:
		message = "Caught ctrl-break event";
		break;
	case CTRL_LOGOFF_EVENT:
		message = "Caught logoff event";
		break;
	case CTRL_SHUTDOWN_EVENT:
	default:
		message = "Caught shutdown event";
		break;
	}
	if (!g_provider.expired()) {
		LOG(INFO) << message << "; closing provider.";
		auto sp = g_provider.lock();
		sp->Quit();
	} else {
		LOG(WARNING) << message << "; provider already expired.";
	}
	return TRUE;
}

void
anaguma::anaguma_t::MainLoop()
{
/* Add shutdown handler. */
	::SetConsoleCtrlHandler ((PHANDLER_ROUTINE)::CtrlHandler, TRUE);
	provider_->Run();
/* Remove shutdown handler. */
	::SetConsoleCtrlHandler ((PHANDLER_ROUTINE)::CtrlHandler, FALSE);
}

void
anaguma::anaguma_t::Clear()
{
/* Close provider client set first */
	if ((bool)provider_) {
		provider_->Close();
	}
	CHECK_LE (provider_.use_count(), 1);
	provider_.reset();
/* Release everything with an UPA dependency. */
	CHECK_LE (upa_.use_count(), 1);
	upa_.reset();
}

/* eof */