/* UPA context.
 */

#include "upa.hh"

/* UPA 7.4 */
#include <upa/upa.h>

#include "chromium/logging.hh"


anaguma::upa_t::upa_t (const config_t& config) :
	config_ (config)
{
}

anaguma::upa_t::~upa_t()
{
	VLOG(2) << "Closing UPA.";
	if (RSSL_RET_SUCCESS != rsslUninitialize()) {
		LOG(ERROR) << "rsslUninitialize failed, detail unavailable.";
	}
}

bool
anaguma::upa_t::Init()
{
	RsslError upa_err;

/* UPA library state.  As of rssl1.5 rsslInitialize implements reference
 * counting so each call should be matched with a call to rsslUninitialize.
 */
	VLOG(2) << "Initializing UPA.";
	if (RSSL_RET_SUCCESS != rsslInitialize (RSSL_LOCK_NONE, &upa_err)) {
		LOG(ERROR) << "rsslInitialize: { "
			  "\"rsslErrorId\": " << upa_err.rsslErrorId << ""
			", \"sysError\": " << upa_err.sysError << ""
			", \"text\": \"" << upa_err.text << "\""
			" }";
		return false;
	}

	VLOG(3) << "UPA initialization complete.";
	return true;
}

/* UPA is split across three libraries: data, message, transport, each can have
 * different versioning detail.
 */
bool
anaguma::upa_t::VerifyVersion()
{
	RsslLibraryVersionInfo version_info;	/* content is bound to static data within each library */

/* RSSL Data Package library */
	rsslQueryDataLibraryVersion (&version_info);
	if (nullptr == strstr (version_info.productVersion, "upa" UPA_LIBRARY_VERSION)) {
		LOG(ERROR)
		<< "This program requires version \"" UPA_LIBRARY_VERSION "\""
		    " of the UPA link-time library, but the linked version "
		   "is \"" << version_info.productVersion << "\".  Please update "
		   "your library.  If you compiled the program yourself, make sure that "
		   "your headers are from the same version of UPA as your "
		   "link-time library.";
		return false;
	} else {
		LOG(INFO) << "RsslDataLibrary: { "
			  "\"productVersion\": \"" << version_info.productVersion << "\""
			", \"internalVersion\": \"" << version_info.internalVersion << "\""
			", \"productDate\": \"" << version_info.productDate << "\""
			" }";

	}
/* RSSL Message Package library */
	rsslQueryMessagesLibraryVersion (&version_info);
	if (nullptr == strstr (version_info.productVersion, "upa" UPA_LIBRARY_VERSION)) {
		LOG(ERROR)
		<< "This program requires version \"" UPA_LIBRARY_VERSION "\""
		    " of the UPA link-time library, but the linked version "
		   "is \"" << version_info.productVersion << "\".  Please update "
		   "your library.  If you compiled the program yourself, make sure that "
		   "your headers are from the same version of UPA as your "
		   "link-time library.";
		return false;
	} else {
		LOG(INFO) << "RsslMessageLibrary: { "
			  "\"productVersion\": \"" << version_info.productVersion << "\""
			", \"internalVersion\": \"" << version_info.internalVersion << "\""
			", \"productDate\": \"" << version_info.productDate << "\""
			" }";
	}

/* RSSL Transport Package library */
	rsslQueryTransportLibraryVersion (&version_info);
	if (nullptr == strstr (version_info.productVersion, "upa" UPA_LIBRARY_VERSION)) {
		LOG(ERROR)
		<< "This program requires version \"" UPA_LIBRARY_VERSION "\""
		    " of the UPA link-time library, but the linked version "
		   "is \"" << version_info.productVersion << "\".  Please update "
		   "your library.  If you compiled the program yourself, make sure that "
		   "your headers are from the same version of UPA as your "
		   "link-time library.";
		return false;
	} else {
		LOG(INFO) << "RsslTransportLibrary: { "
			  "\"productVersion\": \"" << version_info.productVersion << "\""
			", \"internalVersion\": \"" << version_info.internalVersion << "\""
			", \"productDate\": \"" << version_info.productDate << "\""
			" }";
	}
	return true;
}

/* eof */