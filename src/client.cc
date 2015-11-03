/* UPA provider client session.
 */

#include "client.hh"

#include <algorithm>
#include <utility>

#include <windows.h>

#include "chromium/logging.hh"
#include "chromium/string_piece.hh"
#include "googleurl/url_parse.h"
//#include "error.hh"
#include "upaostream.hh"
#include "provider.hh"
#include "worldbank.hh"


#define MAX_MSG_SIZE 4096

/* RDM FIDs. */
static const int kRdmProductPermissionId	= 1;
static const int kRdmPreferredDisplayTemplateId	= 1080;

static const int kRdmBackroundReferenceId	= 967;
static const int kRdmGeneralText1Id		= 1000;
static const int kRdmGeneralText2Id		= 1001;
static const int kRdmPrimaryActivity1Id		= 393;
static const int kRdmSecondActivity1Id		= 275;
static const int kRdmContributor1Id		= 831;
static const int kRdmContributorLocation1Id	= 836;
static const int kRdmContributorPage1Id		= 841;
static const int kRdmDealingCode1Id		= 826;
static const int kRdmActivityTime1Id		= 1010;
static const int kRdmActivityDate1Id		= 875;

/* http://en.wikipedia.org/wiki/Unix_epoch */
static const boost::gregorian::date kUnixEpoch (1970, 1, 1);


/* Convert Posix time to Unix Epoch time.
 */
template< typename TimeT >
inline
TimeT
to_unix_epoch (
	const boost::posix_time::ptime t
	)
{
	return (t - boost::posix_time::ptime (kUnixEpoch)).total_seconds();
}

anaguma::client_t::client_t (
	std::shared_ptr<anaguma::provider_t> provider,
	RsslChannel* handle,
	const char* address
	) :
	creation_time_ (boost::posix_time::second_clock::universal_time()),
	last_activity_ (creation_time_),
	provider_ (provider),
	address_ (address),
	handle_ (handle),
	pending_count_ (0),
	is_logged_in_ (false),
	login_token_ (0)
{
	ZeroMemory (cumulative_stats_, sizeof (cumulative_stats_));
	ZeroMemory (snap_stats_, sizeof (snap_stats_));

/* Set logger ID */
	std::ostringstream ss;
	ss << handle_ << ':';
	prefix_.assign (ss.str());
}

anaguma::client_t::~client_t()
{
	DLOG(INFO) << "~client_t";
/* Remove reference on containing provider. */
	provider_.reset();

	using namespace boost::posix_time;
	const auto uptime = second_clock::universal_time() - creation_time_;
	VLOG(3) << prefix_ << "Summary: {"
		 " \"Uptime\": \"" << to_simple_string (uptime) << "\""
		", \"MsgsReceived\": " << cumulative_stats_[CLIENT_PC_UPA_MSGS_RECEIVED] <<
		", \"MsgsSent\": " << cumulative_stats_[CLIENT_PC_UPA_MSGS_SENT] <<
		", \"MsgsRejected\": " << cumulative_stats_[CLIENT_PC_UPA_MSGS_REJECTED] <<
		" }";
}

bool
anaguma::client_t::Init()
{
	RsslChannelInfo info;
	RsslError rssl_err;
	RsslRet rc;

	DCHECK(nullptr != handle_);
	last_activity_ = boost::posix_time::second_clock::universal_time();

/* Store negotiated Reuters Wire Format version information. */
	rc = rsslGetChannelInfo (handle_, &info, &rssl_err);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslGetChannelInfo: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			" }";
		return false;
	}

/* Log connected infrastructure. */
	std::stringstream components;
	for (unsigned i = 0; i < info.componentInfoCount; ++i) {
		if (i > 0) components << ", ";
		components << "{ "
			"\"" << info.componentInfo[i]->componentVersion.data << "\""
			" }";
	}

/* Relog negotiated state. */
	std::stringstream client_hostname, client_ip;
	if (nullptr == handle_->clientHostname) 
		client_hostname << "null";
	else	
		client_hostname << '"' << handle_->clientHostname << '"';
	if (nullptr == handle_->clientIP)	
		client_ip << "null";
	else	
		client_ip << '"' << handle_->clientIP << '"';
	LOG(INFO) << prefix_ <<
		  "RSSL negotiated state: { "
		  "\"clientHostname\": " << client_hostname.str() << ""
		", \"clientIP\": " << client_ip.str() << ""
		", \"connectionType\": \"" << internal::connection_type_string (handle_->connectionType) << "\""
		", \"majorVersion\": " << (unsigned)GetRwfMajorVersion() << ""
		", \"minorVersion\": " << (unsigned)GetRwfMinorVersion() << ""
		", \"pingTimeout\": " << handle_->pingTimeout << ""
		", \"protocolType\": " << handle_->protocolType << ""
		", \"socketId\": " << handle_->socketId << ""
		", \"state\": \"" << internal::channel_state_string (handle_->state) << "\""
		" }";
/* Derive expected RSSL ping interval from negotiated timeout. */
	ping_interval_ = handle_->pingTimeout / 3;
/* Schedule first RSSL ping. */
	next_ping_ = last_activity_ + boost::posix_time::seconds (ping_interval_);
/* Treat connect as first RSSL pong. */
	next_pong_ = last_activity_ + boost::posix_time::seconds (handle_->pingTimeout);
	return true;
}

/* Propagate close notification to RSSL channel before closing the socket.
 */
bool
anaguma::client_t::Close()
{
/* client_t exists when client session is active but not necessarily logged in. */
	if (is_logged_in_) {
		return SendClose (login_token_,
				  provider_->GetServiceId(),
				  RSSL_DMT_LOGIN,
				  nullptr,
				  0,
				  false, /* no AttribInfo in MMT_LOGIN */
				  RSSL_SC_NONE);
	} else {
		return true;
	}
}

/* Returns true if message processed successfully, returns false to abort the connection.
 */
bool
anaguma::client_t::OnMsg (
	const RsslMsg* msg
	)
{
	DCHECK (nullptr != msg);
	cumulative_stats_[CLIENT_PC_UPA_MSGS_RECEIVED]++;
	switch (msg->msgBase.msgClass) {
	case RSSL_MC_REQUEST:
		return OnRequestMsg (reinterpret_cast<const RsslRequestMsg*> (msg));
	case RSSL_MC_CLOSE:
		return OnCloseMsg (reinterpret_cast<const RsslCloseMsg*> (msg));
	case RSSL_MC_REFRESH:
	case RSSL_MC_STATUS:
	case RSSL_MC_UPDATE:
	case RSSL_MC_ACK:
	case RSSL_MC_GENERIC:
	case RSSL_MC_POST:
	default:
		cumulative_stats_[CLIENT_PC_UPA_MSGS_REJECTED]++;
		LOG(WARNING) << prefix_ << "Uncaught message: " << msg;
/* abort connection if status message fails. */
		return SendClose (msg->msgBase.streamId,
				  msg->msgBase.msgKey.serviceId,
				  msg->msgBase.domainType,
				  msg->msgBase.msgKey.name.data,
				  msg->msgBase.msgKey.name.length,
				  true, /* always send AttribInfo */
				  RSSL_SC_USAGE_ERROR);
	}
}

/* Returns true if message processed successfully, returns false to abort the connection.
 */
bool
anaguma::client_t::OnRequestMsg (
	const RsslRequestMsg* request_msg
	)
{
	cumulative_stats_[CLIENT_PC_REQUEST_MSGS_RECEIVED]++;
	switch (request_msg->msgBase.domainType) {
	case RSSL_DMT_LOGIN:
		return OnLoginRequest (request_msg);
	case RSSL_DMT_SOURCE:	/* Directory */
		return OnDirectoryRequest (request_msg);
	case RSSL_DMT_DICTIONARY:
		return OnDictionaryRequest (request_msg);
	case RSSL_DMT_MARKET_PRICE:
	case RSSL_DMT_MARKET_BY_ORDER:
	case RSSL_DMT_MARKET_BY_PRICE:
	case RSSL_DMT_MARKET_MAKER:
	case RSSL_DMT_SYMBOL_LIST:
	case RSSL_DMT_YIELD_CURVE:
		return OnItemRequest (request_msg);
	default:
		cumulative_stats_[CLIENT_PC_REQUEST_MSGS_REJECTED]++;
		LOG(WARNING) << prefix_ << "Uncaught request message: " << request_msg;
/* abort connection if status message fails. */
		return SendClose (request_msg->msgBase.streamId,
				  request_msg->msgBase.msgKey.serviceId,
				  request_msg->msgBase.domainType,
				  request_msg->msgBase.msgKey.name.data,
				  request_msg->msgBase.msgKey.name.length,
				  RSSL_RQMF_MSG_KEY_IN_UPDATES == (request_msg->flags & RSSL_RQMF_MSG_KEY_IN_UPDATES),
				  RSSL_SC_USAGE_ERROR);
	}
}

/* 7.3. Perform Login Process.
 * The message model type MMT_LOGIN represents a login request. Specific
 * information about the user e.g., name,name type, permission information,
 * single open, etc is available from the AttribInfo in the ReqMsg accessible
 * via getAttribInfo(). The Provider is responsible for processing this
 * information to determine whether to accept the login request.
 *
 * RFA assumes default values for all attributes not specified in the Provider’s
 * login response. For example, if a provider does not specify SingleOpen
 * support in its login response, RFA assumes the provider supports it.
 *
 *   InteractionType:     Streaming request || Pause request.
 *   QualityOfServiceReq: Not used.
 *   Priority:            Not used.
 *   Header:              Not used.
 *   Payload:             Not used.
 *
 * RDM 3.4.4 Authentication: multiple logins per client session are not supported.
 */
bool
anaguma::client_t::OnLoginRequest (
	const RsslRequestMsg* login_msg
	)
{
	cumulative_stats_[CLIENT_PC_MMT_LOGIN_RECEIVED]++;

	static const uint16_t streaming_request = RSSL_RQMF_STREAMING;
	static const uint16_t pause_request     = RSSL_RQMF_PAUSE;

	const bool is_streaming_request = ((streaming_request == login_msg->flags)
					|| ((streaming_request | pause_request) == login_msg->flags));
	const bool is_pause_request     = (pause_request == login_msg->flags);

/* RDM 3.2.4: All message types except GenericMsg should include an AttribInfo.
 * RFA example code verifies existence of AttribInfo with an assertion.
 */
	const bool has_attribinfo = true;
	const bool has_name       = has_attribinfo && (RSSL_MKF_HAS_NAME      == (login_msg->msgBase.msgKey.flags & RSSL_MKF_HAS_NAME));
	const bool has_nametype   = has_attribinfo && (RSSL_MKF_HAS_NAME_TYPE == (login_msg->msgBase.msgKey.flags & RSSL_MKF_HAS_NAME_TYPE));

	LOG(INFO) << prefix_
		  << "is_streaming_request: " << is_streaming_request
		<< ", is_pause_request: " << is_pause_request
		<< ", has_attribinfo: " << has_attribinfo
		<< ", has_name: " << has_name
		<< ", has_nametype: " << has_nametype;

/* invalid RDM login. */
	if ((!is_streaming_request && !is_pause_request)
		|| !has_attribinfo
		|| !has_name
		|| !has_nametype)
	{
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_MALFORMED]++;
		LOG(WARNING) << prefix_ << "Rejecting MMT_LOGIN as RDM validation failed: " << login_msg;
		return RejectLogin (login_msg, login_msg->msgBase.streamId);
	}
	else
	{
		if (!AcceptLogin (login_msg, login_msg->msgBase.streamId)) {
/* disconnect on failure. */
			return false;
		} else {
			is_logged_in_ = true;
			login_token_ = login_msg->msgBase.streamId;
		}
	}

	return true;
}

/** Rejecting Login **
 * In the case where the Provider rejects the login, it should create a RespMsg
 * as above, but set the RespType and RespStatus to the reject semantics
 * specified in RFA API 7 RDM Usage Guide. The provider application should
 * populate an OMMSolicitedItemCmd with this RespMsg, set the corresponding
 * request token and call submit() on the OMM Provider.
 *
 * Once the Provider determines that the login is to be logged out (rejected),
 * it is responsible to clean up all references to request tokens for that
 * particular client session. In addition, any incoming requests that may be
 * received after the login rejection has been submitted should be ignored.
 *
 * NB: The provider application can reject a login at any time after it has
 *     accepted a particular login.
 */
bool
anaguma::client_t::RejectLogin (
	const RsslRequestMsg* login_msg,
	int32_t login_token
	)
{
#ifndef NDEBUG
/* Static initialisation sets all fields rather than only the minimal set
 * required.  Use for debug mode and optimise for release builds.
 */
	RsslStatusMsg response = RSSL_INIT_STATUS_MSG;
	RsslEncodeIterator it = RSSL_INIT_ENCODE_ITERATOR;
#else
	RsslStatusMsg response;
	RsslEncodeIterator it;
	rsslClearStatusMsg (&response);
	rsslClearEncodeIterator (&it);
#endif
	RsslBuffer* buf;
	RsslError rssl_err;
	RsslRet rc;

	VLOG(2) << prefix_ << "Sending MMT_LOGIN rejection.";

/* Set the message model type. */
	response.msgBase.domainType = RSSL_DMT_LOGIN;
/* Set response type. */
	response.msgBase.msgClass = RSSL_MC_STATUS;
/* No payload. */
	response.msgBase.containerType = RSSL_DT_NO_DATA;
/* Set the login token. */
	response.msgBase.streamId = login_token;

/* Item interaction state. */
	response.state.streamState = RSSL_STREAM_CLOSED;
/* Data quality state. */
	response.state.dataState = RSSL_DATA_SUSPECT;
/* Error code. */
	response.state.code = RSSL_SC_NOT_ENTITLED; // RSSL_SC_TOO_MANY_ITEMS would be more suitable, but does not follow RDM spec.
	response.flags |= RSSL_STMF_HAS_STATE;

	buf = rsslGetBuffer (handle_, MAX_MSG_SIZE, RSSL_FALSE /* not packed */, &rssl_err);
	if (nullptr == buf) {
		LOG(ERROR) << prefix_ << "rsslGetBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			", \"size\": " << MAX_MSG_SIZE << ""
			", \"packedBuffer\": false"
			" }";
		return false;
	}
	rc = rsslSetEncodeIteratorBuffer (&it, buf);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorBuffer: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	rc = rsslSetEncodeIteratorRWFVersion (&it, GetRwfMajorVersion(), GetRwfMinorVersion());
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorRWFVersion: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"majorVersion\": " << static_cast<unsigned> (GetRwfMajorVersion()) << ""
			", \"minorVersion\": " << static_cast<unsigned> (GetRwfMinorVersion()) << ""
			" }";
		goto cleanup;
	}
	rc = rsslEncodeMsg (&it, reinterpret_cast<RsslMsg*> (&response));
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsg: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	buf->length = rsslGetEncodedBufferLength (&it);
	LOG_IF(WARNING, 0 == buf->length) << prefix_ << "rsslGetEncodedBufferLength returned 0.";

/* Message validation: must use ASSERT libraries for error description :/ */
	if (!rsslValidateMsg (reinterpret_cast<RsslMsg*> (&response))) {
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_RESPONSE_MALFORMED]++;
		LOG(ERROR) << prefix_ << "rsslValidateMsg failed.";
		goto cleanup;
	} else {
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_RESPONSE_VALIDATED]++;
		LOG(INFO) << prefix_ << "rsslValidateMsg succeeded.";
	}

	if (!Submit (buf)) {
		goto cleanup;
	}
	cumulative_stats_[CLIENT_PC_MMT_LOGIN_REJECTED]++;
	return true;
cleanup:
	cumulative_stats_[CLIENT_PC_MMT_LOGIN_EXCEPTION]++;
	if (RSSL_RET_SUCCESS != rsslReleaseBuffer (buf, &rssl_err)) {
		LOG(WARNING) << prefix_ << "rsslReleaseBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			" }";
	}
	return false;
}

/** Accepting Login **
 * In the case where the Provider accepts the login, it should create a RespMsg
 * with RespType and RespStatus set according to RFA API 7 RDM Usage Guide. The
 * provider application should populate an OMMSolicitedItemCmd with this
 * RespMsg, set the corresponding request token and call submit() on the OMM
 * Provider.
 *
 * NB: There can only be one login per client session.
 */
bool
anaguma::client_t::AcceptLogin (
	const RsslRequestMsg* login_msg,
	int32_t login_token
	)
{
#ifndef NDEBUG
	RsslRefreshMsg response = RSSL_INIT_REFRESH_MSG;
	RsslEncodeIterator it = RSSL_INIT_ENCODE_ITERATOR;
	RsslElementList	element_list = RSSL_INIT_ELEMENT_LIST;
	RsslElementEntry element_entry = RSSL_INIT_ELEMENT_ENTRY;
#else
	RsslRefreshMsg response;
	RsslEncodeIterator it;
	RsslElementList	element_list;
	RsslElementEntry element_entry;
	rsslClearRefreshMsg (&response);
	rsslClearEncodeIterator (&it);
	rsslClearElementList (&element_list);
	rsslClearElementEntry (&element_entry);
#endif
	RsslBuffer* buf;
	RsslError rssl_err;
	RsslRet rc;

	VLOG(2) << prefix_ << "Sending MMT_LOGIN accepted.";

/* Set the message model type. */
	response.msgBase.domainType = RSSL_DMT_LOGIN;
/* Set response type. */
	response.msgBase.msgClass = RSSL_MC_REFRESH;
	response.flags = RSSL_RFMF_SOLICITED | RSSL_RFMF_REFRESH_COMPLETE;
/* No payload. */
	response.msgBase.containerType = RSSL_DT_NO_DATA;
/* Set the login token. */
	response.msgBase.streamId = login_token;

/* In RFA lingo an attribute object */
	response.msgBase.msgKey.nameType = login_msg->msgBase.msgKey.nameType;
	response.msgBase.msgKey.name.data = login_msg->msgBase.msgKey.name.data;
	response.msgBase.msgKey.name.length = login_msg->msgBase.msgKey.name.length;
	response.msgBase.msgKey.flags = RSSL_MKF_HAS_NAME_TYPE | RSSL_MKF_HAS_NAME;
	response.flags |= RSSL_RFMF_HAS_MSG_KEY;

/* RDM 3.3.2 Login Response Elements */
	response.msgBase.msgKey.attribContainerType = RSSL_DT_ELEMENT_LIST;
	response.msgBase.msgKey.flags |= RSSL_MKF_HAS_ATTRIB;

/* Item interaction state. */
	response.state.streamState = RSSL_STREAM_OPEN;
/* Data quality state. */
	response.state.dataState = RSSL_DATA_OK;
/* Error code. */
	response.state.code = RSSL_SC_NONE;

	buf = rsslGetBuffer (handle_, MAX_MSG_SIZE, RSSL_FALSE /* not packed */, &rssl_err);
	if (nullptr == buf) {
		LOG(ERROR) << prefix_ << "rsslGetBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			", \"size\": " << MAX_MSG_SIZE << ""
			", \"packedBuffer\": false"
			" }";
		return false;
	}	
	rc = rsslSetEncodeIteratorBuffer (&it, buf);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorBuffer: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	rc = rsslSetEncodeIteratorRWFVersion (&it, GetRwfMajorVersion(), GetRwfMinorVersion());
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorRWFVersion: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"majorVersion\": " << static_cast<unsigned> (GetRwfMajorVersion()) << ""
			", \"minorVersion\": " << static_cast<unsigned> (GetRwfMinorVersion()) << ""
			" }";
		goto cleanup;
	}
	rc = rsslEncodeMsgInit (&it, reinterpret_cast<RsslMsg*> (&response), MAX_MSG_SIZE);
	if (RSSL_RET_ENCODE_MSG_KEY_OPAQUE != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsgInit: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"dataMaxSize\": " << MAX_MSG_SIZE << ""
			" }";
		goto cleanup;
	}

/* Encode attribute object after message instead of before as per RFA. */
	element_list.flags = RSSL_ELF_HAS_STANDARD_DATA;
	rc = rsslEncodeElementListInit (&it, &element_list, nullptr /* element id dictionary */, 4 /* count of elements */);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeElementListInit: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"flags\": \"RSSL_ELF_HAS_STANDARD_DATA\""
			" }";
		goto cleanup;
	}

/* Images and & updates could be stale. */
	static const uint64_t allow_suspect_data = 1;
	element_entry.dataType	= RSSL_DT_UINT;
	element_entry.name	= RSSL_ENAME_ALLOW_SUSPECT_DATA;
	rc = rsslEncodeElementEntry (&it, &element_entry, &allow_suspect_data);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeElementEntry: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"name\": \"RSSL_ENAME_ALLOW_SUSPECT_DATA\""
			", \"dataType\": \"" << rsslDataTypeToString (element_entry.dataType) << "\""
			", \"allowSuspectData\": " << allow_suspect_data << ""
			" }";
		return false;
	}
/* No permission expressions. */
	static const uint64_t provide_permission_expressions = 0;
	element_entry.dataType	= RSSL_DT_UINT;
	element_entry.name	= RSSL_ENAME_PROV_PERM_EXP;
	rc = rsslEncodeElementEntry (&it, &element_entry, &provide_permission_expressions);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeElementEntry: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"name\": \"RSSL_ENAME_PROV_PERM_EXP\""
			", \"dataType\": \"" << rsslDataTypeToString (element_entry.dataType) << "\""
			", \"providePermissionExpressions\": " << provide_permission_expressions << ""
			" }";
		goto cleanup;
	}
/* No permission profile. */
	static const uint64_t provide_permission_profile = 0;
	element_entry.dataType	= RSSL_DT_UINT;
	element_entry.name	= RSSL_ENAME_PROV_PERM_PROF;
	rc = rsslEncodeElementEntry (&it, &element_entry, &provide_permission_profile);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeElementEntry: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"name\": \"RSSL_ENAME_PROV_PERM_PROF\""
			", \"dataType\": \"" << rsslDataTypeToString (element_entry.dataType) << "\""
			", \"providePermissionProfile\": " << provide_permission_profile << ""
			" }";
		goto cleanup;
	}
/* Downstream application drives stream recovery. */
	static const uint64_t single_open = 0;
	element_entry.dataType	= RSSL_DT_UINT;
	element_entry.name	= RSSL_ENAME_SINGLE_OPEN;
	rc = rsslEncodeElementEntry (&it, &element_entry, &single_open);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeElementEntry: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"name\": \"RSSL_ENAME_SINGLE_OPEN\""
			", \"dataType\": \"" << rsslDataTypeToString (element_entry.dataType) << "\""
			", \"singleOpen\": " << single_open << ""
			" }";
		goto cleanup;
	}
/* Batch requests not supported. */
/* OMM posts not supported. */
/* Optimized pause and resume not supported. */
/* Views not supported. */
/* Warm standby not supported. */
/* Binding complete. */
	rc = rsslEncodeElementListComplete (&it, RSSL_TRUE /* commit */);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeElementListComplete: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	rc = rsslEncodeMsgKeyAttribComplete (&it, RSSL_TRUE /* commit */);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsgKeyAttribComplete: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	if (RSSL_RET_SUCCESS != rsslEncodeMsgComplete (&it, RSSL_TRUE /* commit */)) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsgComplete: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	buf->length = rsslGetEncodedBufferLength (&it);
	LOG_IF(WARNING, 0 == buf->length) << prefix_ << "rsslGetEncodedBufferLength returned 0.";

/* Message validation: must use ASSERT libraries for error description :/ */
//	if (!rsslValidateMsg (reinterpret_cast<RsslMsg*> (&response))) {
//		cumulative_stats_[CLIENT_PC_MMT_LOGIN_RESPONSE_MALFORMED]++;
//		LOG(ERROR) << prefix_ << "rsslValidateMsg failed.";
//		goto cleanup;
//	} else {
//		cumulative_stats_[CLIENT_PC_MMT_LOGIN_RESPONSE_VALIDATED]++;
//		LOG(INFO) << prefix_ << "rsslValidateMsg succeeded.";
//	}

	if (!Submit (buf)) {
		goto cleanup;
	}
	cumulative_stats_[CLIENT_PC_MMT_LOGIN_ACCEPTED]++;
	return true;
cleanup:
	cumulative_stats_[CLIENT_PC_MMT_LOGIN_EXCEPTION]++;
	if (RSSL_RET_SUCCESS != rsslReleaseBuffer (buf, &rssl_err)) {
		LOG(WARNING) << prefix_ << "rsslReleaseBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			" }";
	}
	return false;
}

/* 7.4. Provide Source Directory Information.
 * RDM 4.2.1 ReqMsg
 * Streaming request or Nonstreaming request. No special semantics or
 * restrictions. Pause request is not supported.
 */
bool
anaguma::client_t::OnDirectoryRequest (
	const RsslRequestMsg* request_msg
	)
{
	cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_REQUEST_RECEIVED]++;

	static const uint16_t streaming_request = RSSL_RQMF_STREAMING;
/* NB: snapshot_request == !streaming_request */

	const bool is_streaming_request = (streaming_request == request_msg->flags);
	const bool is_snapshot_request  = !is_streaming_request;

/* RDM 4.2.4 AttribInfo required for ReqMsg. */
	const bool has_attribinfo = true;

/* Filtering of directory contents. */
	const bool has_service_name = has_attribinfo && (RSSL_MKF_HAS_NAME       == (request_msg->msgBase.msgKey.flags & RSSL_MKF_HAS_NAME));
	const bool has_service_id   = has_attribinfo && (RSSL_MKF_HAS_SERVICE_ID == (request_msg->msgBase.msgKey.flags & RSSL_MKF_HAS_SERVICE_ID));
	const uint32_t filter_mask  = request_msg->msgBase.msgKey.filter;

	const int32_t request_token = request_msg->msgBase.streamId;
directory_token_ = request_token;
	if (has_service_name)
	{
		const char* service_name = request_msg->msgBase.msgKey.name.data;
		return SendDirectoryResponse (request_token, service_name, filter_mask);
	}
	else if (has_service_id && 0 != request_msg->msgBase.msgKey.serviceId)
	{
		const uint16_t service_id = request_msg->msgBase.msgKey.serviceId;
		if (service_id == provider_->GetServiceId()) {
			return SendDirectoryResponse (request_token, provider_->GetServiceName(), filter_mask);
		} else {
/* default to full directory if id does not match */
			LOG(WARNING) << prefix_ << "Received MMT_DIRECTORY request for unknown service id #" << service_id << ", returning entire directory.";
			return SendDirectoryResponse (request_token, nullptr, filter_mask);
		}
	}
/* Provide all services directory. */
	else
	{
		return SendDirectoryResponse (request_token, nullptr, filter_mask);
	}
}

bool
anaguma::client_t::OnDictionaryRequest (
	const RsslRequestMsg* request_msg
	)
{
	cumulative_stats_[CLIENT_PC_MMT_DICTIONARY_REQUEST_RECEIVED]++;
	LOG(INFO) << prefix_ << "DictionaryRequest:" << request_msg;

/* Unsupported for this provider and declared so in the directory. */
	return SendClose (request_msg->msgBase.streamId,
			  request_msg->msgBase.msgKey.serviceId,
			  request_msg->msgBase.domainType,
			  request_msg->msgBase.msgKey.name.data,
			  request_msg->msgBase.msgKey.name.length,
			  RSSL_RQMF_MSG_KEY_IN_UPDATES == (request_msg->flags & RSSL_RQMF_MSG_KEY_IN_UPDATES),
			  RSSL_SC_USAGE_ERROR);
}

bool
anaguma::client_t::OnItemRequest (
	const RsslRequestMsg* request_msg
	)
{
	cumulative_stats_[CLIENT_PC_ITEM_REQUEST_RECEIVED]++;
	LOG(INFO) << prefix_ << "ItemRequest:" << request_msg;

/* 10.3.6 Handling Item Requests
 * - Ensure that the requesting session is logged in.
 * - Determine whether the requested QoS can be satisified.
 * - Ensure that the same stream is not already provisioned.
 */

/* A response is not required to be immediately generated, for example
 * forwarding the clients request to an upstream resource and waiting for
 * a reply.
 */
	const uint16_t service_id    = request_msg->msgBase.msgKey.serviceId;
	const uint8_t  model_type    = request_msg->msgBase.domainType;
	const char*    item_name     = request_msg->msgBase.msgKey.name.data;
	const size_t   item_name_len = request_msg->msgBase.msgKey.name.length;
	const bool use_attribinfo_in_updates = (0 != (request_msg->flags & RSSL_RQMF_MSG_KEY_IN_UPDATES));

/* 7.4.3.2 Request Tokens
 * Providers should not attempt to submit data after the provider has received a close request for an item. */
	const int32_t request_token = request_msg->msgBase.streamId;

	if (!is_logged_in_) {
		cumulative_stats_[CLIENT_PC_ITEM_REQUEST_REJECTED]++;
		cumulative_stats_[CLIENT_PC_ITEM_REQUEST_BEFORE_LOGIN]++;
		LOG(INFO) << prefix_ << "Closing request for client without accepted login.";
		return SendClose (request_token, service_id, model_type, item_name, item_name_len, use_attribinfo_in_updates, RSSL_SC_USAGE_ERROR);
	}

{
	std::string ric (item_name, item_name_len);
	if (0 == ric.compare ("DOWN")) {
		LOG(INFO) << "Setting DOWN ...";
		provider_->service_state_ = RDM_DIRECTORY_SERVICE_STATE_DOWN;
		for (auto it = provider_->clients_.begin(); it != provider_->clients_.end(); ++it) {
			auto client = it->second;
			client->SendDirectoryUpdate (provider_->GetServiceName());
		}		
		return SendClose (request_token, service_id, model_type, item_name, item_name_len, use_attribinfo_in_updates, RSSL_SC_NOT_ENTITLED);
	}
	if (0 == ric.compare ("UP")) {
		provider_->service_state_ = RDM_DIRECTORY_SERVICE_STATE_UP;
		LOG(INFO) << "Setting UP ...";
		for (auto it = provider_->clients_.begin(); it != provider_->clients_.end(); ++it) {
			auto client = it->second;
			client->SendDirectoryUpdate (provider_->GetServiceName());
		}		
		return SendClose (request_token, service_id, model_type, item_name, item_name_len, use_attribinfo_in_updates, RSSL_SC_NOT_ENTITLED);
	}
}

/* Only accept MMT_MARKET_PRICE. */
	if (RSSL_DMT_MARKET_PRICE != model_type)
	{
		cumulative_stats_[CLIENT_PC_ITEM_REQUEST_REJECTED]++;
		cumulative_stats_[CLIENT_PC_ITEM_REQUEST_MALFORMED]++;
		LOG(INFO) << prefix_ << "Closing request for unsupported message model type.";
		return SendClose (request_token, service_id, model_type, item_name, item_name_len, use_attribinfo_in_updates, RSSL_SC_NOT_ENTITLED);
	}

	const bool is_streaming_request = (RSSL_RQMF_STREAMING == (request_msg->flags & RSSL_RQMF_STREAMING));

	if (is_streaming_request)
	{
		return OnItemStreamingRequest (request_msg, request_token);
	}
	else
	{
		return OnItemSnapshotRequest (request_msg, request_token);
	}
}

/* If supported: CLIENT_PC_ITEM_DUPLICATE_SNAPSHOT
 */
bool
anaguma::client_t::OnItemSnapshotRequest (
	const RsslRequestMsg* request_msg,
	int32_t request_token
	)
{
	cumulative_stats_[CLIENT_PC_ITEM_SNAPSHOT_REQUEST_RECEIVED]++;

	const uint16_t service_id    = request_msg->msgBase.msgKey.serviceId;
	const uint8_t  model_type    = request_msg->msgBase.domainType;
	const char*    item_name     = request_msg->msgBase.msgKey.name.data;
	const size_t   item_name_len = request_msg->msgBase.msgKey.name.length;
	const bool use_attribinfo_in_updates = (0 != (request_msg->flags & RSSL_RQMF_MSG_KEY_IN_UPDATES));

/* closest equivalent to not-supported is NotAuthorizedEnum. */
	cumulative_stats_[CLIENT_PC_ITEM_REQUEST_REJECTED]++;
	cumulative_stats_[CLIENT_PC_ITEM_REQUEST_MALFORMED]++;
	LOG(INFO) << prefix_ << "Rejecting unsupported snapshot request.";
	return SendClose (request_token, service_id, model_type, item_name, item_name_len, use_attribinfo_in_updates, RSSL_SC_NOT_ENTITLED);
}

bool
anaguma::client_t::OnItemStreamingRequest (
	const RsslRequestMsg* request_msg,
	int32_t request_token
	)
{
	cumulative_stats_[CLIENT_PC_ITEM_STREAMING_REQUEST_RECEIVED]++;

	const uint16_t service_id    = request_msg->msgBase.msgKey.serviceId;
	const uint8_t  model_type    = request_msg->msgBase.domainType;
	const char*    item_name     = request_msg->msgBase.msgKey.name.data;
	const size_t   item_name_len = request_msg->msgBase.msgKey.name.length;
	const bool use_attribinfo_in_updates = (0 != (request_msg->flags & RSSL_RQMF_MSG_KEY_IN_UPDATES));

/* decompose request */
	DVLOG(4) << prefix_ << "item name: [" << std::string (item_name, item_name_len) << "] len: " << item_name_len;
	url_parse::Parsed parsed;
	url_parse::Component file_name;
	url_.assign ("vta://localhost");
	url_.append (item_name, item_name_len);
	url_parse::ParseStandardURL (url_.c_str(), static_cast<int>(url_.size()), &parsed);
	if (parsed.path.is_valid())
		url_parse::ExtractFileName (url_.c_str(), parsed.path, &file_name);
	if (!file_name.is_valid()) {
		cumulative_stats_[CLIENT_PC_ITEM_REQUEST_REJECTED]++;
		cumulative_stats_[CLIENT_PC_ITEM_REQUEST_MALFORMED]++;
		LOG(INFO) << prefix_ << "Closing invalid request for \"" << std::string (item_name, item_name_len) << "\"";
		return SendClose (request_token, service_id, model_type, item_name, item_name_len, use_attribinfo_in_updates, RSSL_SC_NOT_ENTITLED);
	}
/* require a NULL terminated string */
	underlying_symbol_.assign (url_.c_str() + file_name.begin, file_name.len);

/* extract out timestamp */
	boost::posix_time::ptime timestamp (boost::posix_time::not_a_date_time);
	if (parsed.query.is_valid()) {
		url_parse::Component query = parsed.query;
		url_parse::Component key_range, value_range;
		boost::posix_time::ptime t;

/* For each key-value pair, i.e. ?a=x&b=y&c=z -> (a,x) (b,y) (c,z)
 */
		while (url_parse::ExtractQueryKeyValue (url_.c_str(), &query, &key_range, &value_range))
		{
/* Lazy std::string conversion for key
 */
			const chromium::StringPiece key (url_.c_str() + key_range.begin, key_range.len);
/* Value must convert to add NULL terminator for conversion APIs.
 */
			value_.assign (url_.c_str() + value_range.begin, value_range.len);
			LOG(INFO) << "key [" << key << "]";
			if (key == "t") {
/* Disabling exceptions in boost::posix_time::time_duration requires stringstream which requires a string to initialise.
 */
				iss_.str (value_);
				if (iss_ >> t) {timestamp = t;
				LOG(INFO) << "timestamp = " << timestamp; }
			}
		}
	}
	if (timestamp.is_not_a_date_time())
		timestamp = boost::posix_time::second_clock::local_time();

	if (provider_->AddRequest (request_token, shared_from_this()))
	{
		return SendInitial (service_id, request_token, item_name, item_name_len, timestamp);
/* wait for close */
	}
	else
	{
/* Reissue request for secondary subscribers */
		cumulative_stats_[CLIENT_PC_ITEM_REISSUE_REQUEST_RECEIVED]++;
		return SendInitial (service_id, request_token, item_name, item_name_len, timestamp);
	}
}

bool
anaguma::client_t::OnCloseMsg (
	const RsslCloseMsg* close_msg
	)
{
	cumulative_stats_[CLIENT_PC_CLOSE_MSGS_RECEIVED]++;
	switch (close_msg->msgBase.domainType) {
	case RSSL_DMT_MARKET_PRICE:
	case RSSL_DMT_MARKET_BY_ORDER:
	case RSSL_DMT_MARKET_BY_PRICE:
	case RSSL_DMT_MARKET_MAKER:
	case RSSL_DMT_SYMBOL_LIST:
	case RSSL_DMT_YIELD_CURVE:
		return OnItemClose (close_msg);
	case RSSL_DMT_LOGIN:
/* toggle login status. */
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_CLOSE_RECEIVED]++;
		if (!is_logged_in_) {
			cumulative_stats_[CLIENT_PC_CLOSE_MSGS_DISCARDED]++;
			LOG(WARNING) << prefix_ << "Close on MMT_LOGIN whilst not logged in.";
		} else {
			is_logged_in_ = false;
			login_token_ = 0;
/* TODO: cleanup client state. */
			LOG(INFO) << prefix_ << "Client session logged out.";
		}
		break;
	case RSSL_DMT_SOURCE:	/* Directory */
/* directory subscription maintains no state, close is a no-op. */
		cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_CLOSE_RECEIVED]++;
		LOG(INFO) << prefix_ << "Directory closed.";
		break;
	case RSSL_DMT_DICTIONARY:
/* dictionary is unsupported so a usage error. */
		cumulative_stats_[CLIENT_PC_MMT_DICTIONARY_CLOSE_RECEIVED]++;
	default:
		cumulative_stats_[CLIENT_PC_CLOSE_MSGS_DISCARDED]++;
		LOG(WARNING) << prefix_ << "Uncaught close message: " << close_msg;
		break;
	}

	return true;
}

bool
anaguma::client_t::OnItemClose (
	const RsslCloseMsg* close_msg
	)
{
	cumulative_stats_[CLIENT_PC_ITEM_CLOSE_RECEIVED]++;
	LOG(INFO) << prefix_ << "ItemClose:" << close_msg;

	const uint16_t service_id    = close_msg->msgBase.msgKey.serviceId;
	const uint8_t  model_type    = close_msg->msgBase.domainType;
	const char*    item_name     = close_msg->msgBase.msgKey.name.data;
	const size_t   item_name_len = close_msg->msgBase.msgKey.name.length;
/* Close message does not define this flag, go with lowest common denominator. */
	const bool use_attribinfo_in_updates = true;

/* 7.4.3.2 Request Tokens
 * Providers should not attempt to submit data after the provider has received a close request for an item. */
	const int32_t request_token = close_msg->msgBase.streamId;

	if (!is_logged_in_) {
		cumulative_stats_[CLIENT_PC_CLOSE_MSGS_DISCARDED]++;
		LOG(INFO) << prefix_ << "Discarding close for client without accepted login.";
		return true;
	}

/* Verify domain model */
	if (RSSL_DMT_MARKET_PRICE != model_type)
	{
		cumulative_stats_[CLIENT_PC_CLOSE_MSGS_DISCARDED]++;
		LOG(INFO) << prefix_ << "Discarding close request for unsupported message model type.";
		return true;
	}

	if (!provider_->RemoveRequest (request_token))
	{
		cumulative_stats_[CLIENT_PC_CLOSE_MSGS_DISCARDED]++;
		LOG(INFO) << prefix_ << "Discarding close request on closed item.";
	}
	else
	{		
		cumulative_stats_[CLIENT_PC_ITEM_CLOSED]++;
		DLOG(INFO) << prefix_ << "Closed open request.";
	}
	return true;
}

/* Initial images and refresh images for reissue requests.
 */
bool
anaguma::client_t::SendInitial (
	uint16_t service_id,
	int32_t token,
	const char* name,
	size_t name_len,
	const boost::posix_time::ptime& timestamp
	)
{
/* 7.4.8.1 Create a response message (4.2.2) */
	RsslRefreshMsg response = RSSL_INIT_REFRESH_MSG;
#ifndef NDEBUG
	RsslEncodeIterator it = RSSL_INIT_ENCODE_ITERATOR;
#else
	RsslEncodeIterator it;
	rsslClearEncodeIterator (&it);
#endif
	RsslBuffer* buf;
	RsslError rssl_err;
	RsslRet rc;

/* 7.4.8.3 Set the message model type of the response. */
	response.msgBase.domainType = RSSL_DMT_MARKET_PRICE;
/* 7.4.8.4 Set response type, response type number, and indication mask. */
	response.msgBase.msgClass = RSSL_MC_REFRESH;
/* for snapshot images do not cache */
	response.flags = RSSL_RFMF_SOLICITED        |
			 RSSL_RFMF_REFRESH_COMPLETE |
			 RSSL_RFMF_DO_NOT_CACHE;
/* RDM field list. */
	response.msgBase.containerType = RSSL_DT_FIELD_LIST;

/* 7.4.8.2 Create or re-use a request attribute object (4.2.4) */
	response.msgBase.msgKey.serviceId   = service_id;
	response.msgBase.msgKey.nameType    = RDM_INSTRUMENT_NAME_TYPE_RIC;
	response.msgBase.msgKey.name.data   = const_cast<char*> (name);
	response.msgBase.msgKey.name.length = static_cast<uint32_t> (name_len);
	LOG(INFO) << "data: [" << std::string (name, name_len) << "], length: " << name_len;
	response.msgBase.msgKey.flags = RSSL_MKF_HAS_SERVICE_ID | RSSL_MKF_HAS_NAME_TYPE | RSSL_MKF_HAS_NAME;
	response.flags |= RSSL_RFMF_HAS_MSG_KEY;
/* Set the request token. */
	response.msgBase.streamId = token;

/** Optional: but require to replace stale values in cache when stale values are supported. **/
/* Item interaction state: Open, Closed, ClosedRecover, Redirected, NonStreaming, or Unspecified. */
	response.state.streamState = RSSL_STREAM_OPEN;
/* Data quality state: Ok, Suspect, or Unspecified. */
	response.state.dataState = RSSL_DATA_OK;
/* Error code, e.g. NotFound, InvalidArgument, ... */
	response.state.code = RSSL_SC_NONE;

	buf = rsslGetBuffer (handle_, MAX_MSG_SIZE, RSSL_FALSE /* not packed */, &rssl_err);
	if (nullptr == buf) {
		LOG(ERROR) << prefix_ << "rsslGetBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			", \"size\": " << MAX_MSG_SIZE << ""
			", \"packedBuffer\": false"
			" }";
		return false;
	}
	rc = rsslSetEncodeIteratorBuffer (&it, buf);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorBuffer: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	rc = rsslSetEncodeIteratorRWFVersion (&it, GetRwfMajorVersion(), GetRwfMinorVersion());
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorRWFVersion: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"majorVersion\": " << static_cast<unsigned> (GetRwfMajorVersion()) << ""
			", \"minorVersion\": " << static_cast<unsigned> (GetRwfMinorVersion()) << ""
			" }";
		goto cleanup;
	}
	rc = rsslEncodeMsgInit (&it, reinterpret_cast<RsslMsg*> (&response), /* maximum size */ 0);
	if (RSSL_RET_ENCODE_CONTAINER != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsgInit: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	{
/* 4.3.1 RespMsg.Payload */
/* TIMEACT & ACTIV_DATE */
		struct tm _tm;
		__time32_t time32 = to_unix_epoch<__time32_t> (timestamp);
		_gmtime32_s (&_tm, &time32);

/* Clear required for SingleWriteIterator state machine. */
		RsslFieldList field_list;
		RsslFieldEntry field;
		RsslBuffer data_buffer;
		RsslReal rssl_real;
		RsslTime rssl_time;
		RsslDate rssl_date;

		rsslClearFieldList (&field_list);
		rsslClearFieldEntry (&field);
		rsslClearReal (&rssl_real);

		field_list.flags = RSSL_FLF_HAS_STANDARD_DATA;
		rc = rsslEncodeFieldListInit (&it, &field_list, 0 /* summary data */, 0 /* payload */);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldListInit: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"flags\": \"RSSL_FLF_HAS_STANDARD_DATA\""
				" }";
			goto cleanup;
		}

/* For each field set the Id via a FieldEntry bound to the iterator followed by setting the data.
 * The iterator API provides setters for common types excluding 32-bit floats, with fallback to 
 * a generic DataBuffer API for other types or support of pre-calculated values.
 */
/* PROD_PERM */
		field.fieldId  = kRdmProductPermissionId;
		field.dataType = RSSL_DT_UINT;
		const uint64_t prod_perm = 213;		/* for JPY= */
		rc = rsslEncodeFieldEntry (&it, &field, &prod_perm);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"productPermission\": " << prod_perm << ""
				" }";
			goto cleanup;
		}

/* PREF_DISP */
		field.fieldId  = kRdmPreferredDisplayTemplateId;
		field.dataType = RSSL_DT_UINT;
		const uint64_t pref_disp = 6205;	/* for JPY= */
		rc = rsslEncodeFieldEntry (&it, &field, &pref_disp);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"preferredDisplayTemplate\": " << pref_disp << ""
				" }";
			goto cleanup;
		}

/* BKGD_REF */
		field.fieldId  = kRdmBackroundReferenceId;
		field.dataType = RSSL_DT_ASCII_STRING;
		const std::string bkgd_ref ("Japanese Yen");
		data_buffer.data   = const_cast<char*> (bkgd_ref.c_str());
		data_buffer.length = static_cast<uint32_t> (bkgd_ref.size());
		rc = rsslEncodeFieldEntry (&it, &field, &data_buffer);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"backgroundReference\": \"" << bkgd_ref << "\""
				" }";
			goto cleanup;
		}

/* GV1_TEXT */
		field.fieldId  = kRdmGeneralText1Id;
		field.dataType = RSSL_DT_RMTES_STRING;
		const std::string gv1_text ("SPOT");
		data_buffer.data   = const_cast<char*> (gv1_text.c_str());
		data_buffer.length = static_cast<uint32_t> (gv1_text.size());
		rc = rsslEncodeFieldEntry (&it, &field, &data_buffer);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"generalText1\": \"" << gv1_text << "\""
				" }";
			goto cleanup;
		}

/* GV2_TEXT */
		field.fieldId  = kRdmGeneralText2Id;
		field.dataType = RSSL_DT_RMTES_STRING;
		const std::string gv2_text ("USDJPY");
		data_buffer.data   = const_cast<char*> (gv2_text.c_str());
		data_buffer.length = static_cast<uint32_t> (gv2_text.size());
		rc = rsslEncodeFieldEntry (&it, &field, &data_buffer);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"generalText2\": \"" << gv2_text << "\""
				" }";
			goto cleanup;
		}

/* PRIMACT_1 */
		field.fieldId  = kRdmPrimaryActivity1Id;
		field.dataType = RSSL_DT_REAL;
		const double bid = 82.20;
		rssl_real.value = worldbank::mantissa (bid);
		rssl_real.hint  = RSSL_RH_EXPONENT_2;
		rc = rsslEncodeFieldEntry (&it, &field, &rssl_real);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"primaryActivity1\": { "
					  "\"isBlank\": " << (rssl_real.isBlank ? "true" : "false") << ""
					", \"value\": " << rssl_real.value << ""
					", \"hint\": \"" << internal::real_hint_string (static_cast<RsslRealHints> (rssl_real.hint)) << "\""
				" }"
				" }";
			goto cleanup;
		}

/* SEC_ACT_1 */
		field.fieldId  = kRdmSecondActivity1Id;
		field.dataType = RSSL_DT_REAL;
		const double ask = 82.22;
		rssl_real.value = worldbank::mantissa (ask);
		rssl_real.hint  = RSSL_RH_EXPONENT_2;
		rc = rsslEncodeFieldEntry (&it, &field, &rssl_real);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"secondActivity1\": { "
					  "\"isBlank\": " << (rssl_real.isBlank ? "true" : "false") << ""
					", \"value\": " << rssl_real.value << ""
					", \"hint\": \"" << internal::real_hint_string (static_cast<RsslRealHints> (rssl_real.hint)) << "\""
				" }"
				" }";
			goto cleanup;
		}

/* CTBTR_1 */
		field.fieldId  = kRdmContributor1Id;
		field.dataType = RSSL_DT_RMTES_STRING;
		const std::string ctbtr_1 ("RBS");
		data_buffer.data   = const_cast<char*> (ctbtr_1.c_str());
		data_buffer.length = static_cast<uint32_t> (ctbtr_1.size());
		rc = rsslEncodeFieldEntry (&it, &field, &data_buffer);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"contributor1\": \"" << ctbtr_1 << "\""
				" }";
			goto cleanup;
		}

/* CTB_LOC1 */
		field.fieldId  = kRdmContributorLocation1Id;
		field.dataType = RSSL_DT_RMTES_STRING;
		const std::string ctb_loc1 ("XST");
		data_buffer.data   = const_cast<char*> (ctb_loc1.c_str());
		data_buffer.length = static_cast<uint32_t> (ctb_loc1.size());
		rc = rsslEncodeFieldEntry (&it, &field, &data_buffer);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"contributorLocation1\": \"" << ctb_loc1 << "\""
				" }";
			goto cleanup;
		}

/* CTB_PAGE1 */
		field.fieldId  = kRdmContributorPage1Id;
		field.dataType = RSSL_DT_RMTES_STRING;
		const std::string ctb_page1 ("1RBS");
		data_buffer.data   = const_cast<char*> (ctb_page1.c_str()); 
		data_buffer.length = static_cast<uint32_t> (ctb_page1.size());
		rc = rsslEncodeFieldEntry (&it, &field, &data_buffer);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"contributorPage1\": \"" << ctb_page1 << "\""
				" }";
			goto cleanup;
		}

/* DLG_CODE1 */
		field.fieldId  = kRdmDealingCode1Id;
		field.dataType = RSSL_DT_RMTES_STRING;
		const std::string dlg_code1 ("RBSN");
		data_buffer.data   = const_cast<char*> (dlg_code1.c_str());
		data_buffer.length = static_cast<uint32_t> (dlg_code1.size());
		rc = rsslEncodeFieldEntry (&it, &field, &data_buffer);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"dealingCode1\": \"" << dlg_code1 << "\""
				" }";
			goto cleanup;
		}

/* VALUE_TS1 */
		field.fieldId  = kRdmActivityTime1Id;
		field.dataType = RSSL_DT_TIME;
		rssl_time.hour = _tm.tm_hour; rssl_time.minute = _tm.tm_min; rssl_time.second = _tm.tm_sec; rssl_time.millisecond = 0;
		rc = rsslEncodeFieldEntry (&it, &field, &rssl_time);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"activityTime1\": { "
					  "\"hour\": " << rssl_time.hour << ""
					", \"minute\": " << rssl_time.minute << ""
					", \"second\": " << rssl_time.second << ""
					", \"millisecond\": " << rssl_time.millisecond << ""
				" }"
				" }";
			goto cleanup;
		}

/* VALUE_DT1 */
		field.fieldId  = kRdmActivityDate1Id;
		field.dataType = RSSL_DT_DATE;
		rssl_date.year  = /* upa(yyyy) */ 1900 + _tm.tm_year /* tm(yyyy-1900 */;
		rssl_date.month = /* upa(1-12) */    1 + _tm.tm_mon  /* tm(0-11) */;
		rssl_date.day   = /* upa(1-31) */        _tm.tm_mday /* tm(1-31) */;
		rc = rsslEncodeFieldEntry (&it, &field, &rssl_date);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldEntry: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				", \"fieldId\": " << field.fieldId << ""
				", \"dataType\": \"" << rsslDataTypeToString (field.dataType) << "\""
				", \"activityDate1\": { "
					  "\"year\": " << rssl_date.year << ""
					", \"month\": " << rssl_date.month << ""
					", \"day\": " << rssl_date.day << ""
				" }"
				" }";
			goto cleanup;
		}

		rc = rsslEncodeFieldListComplete (&it, RSSL_TRUE /* commit */);
		if (RSSL_RET_SUCCESS != rc) {
			LOG(ERROR) << prefix_ << "rsslEncodeFieldListComplete: { "
				  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
				", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
				" }";
			goto cleanup;
		}
	}
/* finalize multi-step encoder */
	rc = rsslEncodeMsgComplete (&it, RSSL_TRUE /* commit */);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsgComplete: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	buf->length = rsslGetEncodedBufferLength (&it);
	LOG_IF(WARNING, 0 == buf->length) << prefix_ << "rsslGetEncodedBufferLength returned 0.";

	if (DCHECK_IS_ON()) {
/* Message validation: must use ASSERT libraries for error description :/ */
		if (!rsslValidateMsg (reinterpret_cast<RsslMsg*> (&response))) {
			cumulative_stats_[CLIENT_PC_ITEM_MALFORMED]++;
			LOG(ERROR) << prefix_ << "rsslValidateMsg failed.";
			goto cleanup;
		} else {
			cumulative_stats_[CLIENT_PC_ITEM_VALIDATED]++;
			LOG(INFO) << prefix_ << "rsslValidateMsg succeeded.";
		}
	}

	if (!Submit (buf)) {
		goto cleanup;
	}
	cumulative_stats_[CLIENT_PC_ITEM_SENT]++;
	return true;
cleanup:
	if (RSSL_RET_SUCCESS != rsslReleaseBuffer (buf, &rssl_err)) {
		LOG(WARNING) << prefix_ << "rsslReleaseBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			" }";
	}
	return false;
}

#if 0
/* 7.4.7.1.2 Handling Consumer Client Session Events: Client session connection
 *           has been lost.
 *
 * When the provider receives this event it should stop sending any data to that
 * client session. Then it should remove references to the client session handle
 * and its associated request tokens.
 */
void
anaguma::client_t::OnOMMInactiveClientSessionEvent (
	const rfa::sessionLayer::OMMInactiveClientSessionEvent& session_event
	)
{
	DCHECK(nullptr != handle_);
	cumulative_stats_[CLIENT_PC_OMM_INACTIVE_CLIENT_SESSION_RECEIVED]++;
	try {
/* reject new item requests. */
		is_logged_in_ = false;
/* remove requests from item streams. */
		VLOG(2) << prefix_ << "Removing client from " << items_.size() << " item streams.";
		std::for_each (items_.begin(), items_.end(),
			[&](const std::pair<rfa::sessionLayer::RequestToken*, std::weak_ptr<item_stream_t>>& item)
		{
			auto stream = item.second.lock();
			if (!(bool)stream)
				return;
			boost::upgrade_lock<boost::shared_mutex> lock (stream->lock);
			auto it = stream->requests.find (item.first);
			DCHECK(stream->requests.end() != it);
			boost::upgrade_to_unique_lock<boost::shared_mutex> uniqueLock (lock);
			stream->requests.erase (it);
			VLOG(2) << prefix_ << stream->rfa_name;
		});
/* forward upstream to remove reference to this. */
		provider_->EraseClientSession (handle_);
/* handle is now invalid. */
		handle_ = nullptr;
/* ignore any error */
	} catch (const std::exception& e) {
		LOG(ERROR) << prefix_ << "Exception: { "
			"\"What\": \"" << e.what() << "\" }";
	}
}
#endif

/* 10.3.4 Providing Service Directory (Interactive)
 * A Consumer typically requests a Directory from a Provider to retrieve
 * information about available services and their capabilities, and it is the
 * responsibility of the Provider to encode and supply the directory.
 */
bool
anaguma::client_t::SendDirectoryResponse (
	int32_t request_token,
	const char* service_name,
	uint32_t filter_mask
	)
{
/* 7.5.9.1 Create a response message (4.2.2) */
	RsslRefreshMsg response = RSSL_INIT_REFRESH_MSG;
#ifndef NDEBUG
	RsslEncodeIterator it = RSSL_INIT_ENCODE_ITERATOR;
#else
	RsslEncodeIterator it;
	rsslClearEncodeIterator (&it);
#endif
	RsslBuffer* buf;
	RsslError rssl_err;
	RsslRet rc;

	VLOG(2) << prefix_ << "Sending directory response.";

/* 7.5.9.2 Set the message model type of the response. */
	response.msgBase.domainType = RSSL_DMT_SOURCE;
/* 7.5.9.3 Set response type. */
	response.msgBase.msgClass = RSSL_MC_REFRESH;
/* 7.5.9.4 Set the response type enumeration.
 * Note type is unsolicited despite being a mandatory requirement before
 * publishing.
 */
	response.flags = RSSL_RFMF_SOLICITED | RSSL_RFMF_REFRESH_COMPLETE;
/* Directory map. */
	response.msgBase.containerType = RSSL_DT_MAP;
/* DataMask: required for refresh RespMsg
 *   SERVICE_INFO_FILTER  - Static information about service.
 *   SERVICE_STATE_FILTER - Refresh or update state.
 *   SERVICE_GROUP_FILTER - Transient groups within service.
 *   SERVICE_LOAD_FILTER  - Statistics about concurrent stream support.
 *   SERVICE_DATA_FILTER  - Broadcast data.
 *   SERVICE_LINK_FILTER  - Load balance grouping.
 */
	response.msgBase.msgKey.filter = filter_mask & (RDM_DIRECTORY_SERVICE_INFO_FILTER | RDM_DIRECTORY_SERVICE_STATE_FILTER);
/* Name:        Not used */
/* NameType:    Not used */
/* ServiceName: Not used */
/* ServiceId:   Not used */
/* Id:          Not used */
/* Attrib:      Not used */
	response.msgBase.msgKey.flags = RSSL_MKF_HAS_FILTER;
	response.flags |= RSSL_RFMF_HAS_MSG_KEY;
/* set token */
	response.msgBase.streamId = request_token;

/* Item interaction state. */
	response.state.streamState = RSSL_STREAM_OPEN;
/* Data quality state. */
	response.state.dataState = RSSL_DATA_OK;
/* Error code. */
	response.state.code = RSSL_SC_NONE;

/* pop buffer from RSSL memory pool */
	buf = rsslGetBuffer (handle_, MAX_MSG_SIZE, RSSL_FALSE /* not packed */, &rssl_err);
	if (nullptr == buf) {
		LOG(ERROR) << prefix_ << "rsslGetBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			", \"size\": " << MAX_MSG_SIZE << ""
			", \"packedBuffer\": false"
			" }";
		return false;
	}
/* tie buffer to RSSL write iterator */
	rc = rsslSetEncodeIteratorBuffer (&it, buf);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorBuffer: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
/* encode with clients preferred protocol version */
	rc = rsslSetEncodeIteratorRWFVersion (&it, GetRwfMajorVersion(), GetRwfMinorVersion());
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorRWFVersion: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"majorVersion\": " << static_cast<unsigned> (GetRwfMajorVersion()) << ""
			", \"minorVersion\": " << static_cast<unsigned> (GetRwfMinorVersion()) << ""
			" }";
		goto cleanup;
	}
/* start multi-step encoder */
	rc = rsslEncodeMsgInit (&it, reinterpret_cast<RsslMsg*> (&response), MAX_MSG_SIZE);
	if (RSSL_RET_ENCODE_CONTAINER != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsgInit failed: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"dataMaxSize\": " << MAX_MSG_SIZE << ""
			" }";
		goto cleanup;
	}
/* populate directory map */
	if (!provider_->GetDirectoryMap (&it, service_name, filter_mask, RSSL_MPEA_ADD_ENTRY)) {
		LOG(ERROR) << prefix_ << "GetDirectoryMap failed.";
		goto cleanup;
	}
/* finalize multi-step encoder */
	rc = rsslEncodeMsgComplete (&it, RSSL_TRUE /* commit */);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsgComplete: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	buf->length = rsslGetEncodedBufferLength (&it);
	LOG_IF(WARNING, 0 == buf->length) << prefix_ << "rsslGetEncodedBufferLength returned 0.";

/* Message validation. */
	if (!rsslValidateMsg (reinterpret_cast<RsslMsg*> (&response))) {
		cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_MALFORMED]++;
		LOG(ERROR) << prefix_ << "rsslValidateMsg failed.";
		goto cleanup;
	} else {
		cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_VALIDATED]++;
		LOG(INFO) << prefix_ << "rsslValidateMsg succeeded.";
	}

	if (!Submit (buf)) {
		LOG(ERROR) << prefix_ << "Submit failed.";
		goto cleanup;
	}
	cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_SENT]++;
	return true;
cleanup:
	if (RSSL_RET_SUCCESS != rsslReleaseBuffer (buf, &rssl_err)) {
		LOG(WARNING) << prefix_ << "rsslReleaseBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			" }";
	}
	return false;
}

bool
anaguma::client_t::SendDirectoryUpdate (
	const char* service_name
	)
{
/* 7.5.9.1 Create a response message (4.2.2) */
	RsslUpdateMsg response = RSSL_INIT_UPDATE_MSG;
#ifndef NDEBUG
	RsslEncodeIterator it = RSSL_INIT_ENCODE_ITERATOR;
#else
	RsslEncodeIterator it;
	rsslClearEncodeIterator (&it);
#endif
	RsslBuffer* buf;
	RsslError rssl_err;
	RsslRet rc;

	VLOG(2) << prefix_ << "Sending directory update.";

/* 7.5.9.2 Set the message model type of the response. */
	response.msgBase.domainType = RSSL_DMT_SOURCE;
/* 7.5.9.3 Set response type. */
	response.msgBase.msgClass = RSSL_MC_UPDATE;
/* 7.5.9.4 Set the response type enumeration.
 * Note type is unsolicited despite being a mandatory requirement before
 * publishing.
 */
	response.flags = RSSL_UPMF_DO_NOT_CONFLATE;
/* Directory map. */
	response.msgBase.containerType = RSSL_DT_MAP;
/* DataMask: required for refresh RespMsg
 *   SERVICE_INFO_FILTER  - Static information about service.
 *   SERVICE_STATE_FILTER - Refresh or update state.
 *   SERVICE_GROUP_FILTER - Transient groups within service.
 *   SERVICE_LOAD_FILTER  - Statistics about concurrent stream support.
 *   SERVICE_DATA_FILTER  - Broadcast data.
 *   SERVICE_LINK_FILTER  - Load balance grouping.
 */
	response.msgBase.msgKey.filter = RDM_DIRECTORY_SERVICE_STATE_FILTER;
/* Name:        Not used */
/* NameType:    Not used */
/* ServiceName: Not used */
/* ServiceId:   Not used */
/* Id:          Not used */
/* Attrib:      Not used */
	response.msgBase.msgKey.flags = RSSL_MKF_HAS_FILTER;
	response.flags |= RSSL_UPMF_HAS_MSG_KEY;
/* set token */
	response.msgBase.streamId = directory_token_;

/* pop buffer from RSSL memory pool */
	buf = rsslGetBuffer (handle_, MAX_MSG_SIZE, RSSL_FALSE /* not packed */, &rssl_err);
	if (nullptr == buf) {
		LOG(ERROR) << prefix_ << "rsslGetBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			", \"size\": " << MAX_MSG_SIZE << ""
			", \"packedBuffer\": false"
			" }";
		return false;
	}
/* tie buffer to RSSL write iterator */
	rc = rsslSetEncodeIteratorBuffer (&it, buf);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorBuffer: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
/* encode with clients preferred protocol version */
	rc = rsslSetEncodeIteratorRWFVersion (&it, GetRwfMajorVersion(), GetRwfMinorVersion());
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorRWFVersion: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"majorVersion\": " << static_cast<unsigned> (GetRwfMajorVersion()) << ""
			", \"minorVersion\": " << static_cast<unsigned> (GetRwfMinorVersion()) << ""
			" }";
		goto cleanup;
	}
/* start multi-step encoder */
	rc = rsslEncodeMsgInit (&it, reinterpret_cast<RsslMsg*> (&response), MAX_MSG_SIZE);
	if (RSSL_RET_ENCODE_CONTAINER != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsgInit failed: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"dataMaxSize\": " << MAX_MSG_SIZE << ""
			" }";
		goto cleanup;
	}
/* populate directory map */
	if (!provider_->GetDirectoryMap (&it, service_name, RDM_DIRECTORY_SERVICE_STATE_FILTER, RSSL_MPEA_UPDATE_ENTRY)) {
		LOG(ERROR) << prefix_ << "GetDirectoryMap failed.";
		goto cleanup;
	}
/* finalize multi-step encoder */
	rc = rsslEncodeMsgComplete (&it, RSSL_TRUE /* commit */);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsgComplete: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
				", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	buf->length = rsslGetEncodedBufferLength (&it);
	LOG_IF(WARNING, 0 == buf->length) << prefix_ << "rsslGetEncodedBufferLength returned 0.";

/* Message validation. */
	if (!rsslValidateMsg (reinterpret_cast<RsslMsg*> (&response))) {
		cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_MALFORMED]++;
		LOG(ERROR) << prefix_ << "rsslValidateMsg failed.";
		goto cleanup;
	} else {
		cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_VALIDATED]++;
		LOG(INFO) << prefix_ << "rsslValidateMsg succeeded.";
	}

	if (!Submit (buf)) {
		LOG(ERROR) << prefix_ << "Submit failed.";
		goto cleanup;
	}
	cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_SENT]++;
	return true;
cleanup:
	if (RSSL_RET_SUCCESS != rsslReleaseBuffer (buf, &rssl_err)) {
		LOG(WARNING) << prefix_ << "rsslReleaseBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			" }";
	}
	return false;
}

bool
anaguma::client_t::SendClose (
	int32_t request_token,
	uint16_t service_id,
	uint8_t model_type,
	const char* name,
	size_t name_len,
	bool use_attribinfo_in_updates,
	uint8_t status_code
	)
{
	RsslStatusMsg response = RSSL_INIT_STATUS_MSG;
#ifndef NDEBUG
/* Static initialisation sets all fields rather than only the minimal set
 * required.  Use for debug mode and optimise for release builds.
 */
	RsslEncodeIterator it = RSSL_INIT_ENCODE_ITERATOR;
#else
	RsslEncodeIterator it;
	rsslClearEncodeIterator (&it);
#endif
	RsslBuffer* buf;
	RsslError rssl_err;
	RsslRet rc;

	VLOG(2) << prefix_ << "Sending item close { "
		  "\"RequestToken\": " << request_token << ""
		", \"ServiceID\": " << service_id << ""
		", \"MsgModelType\": " << internal::domain_type_string (static_cast<RsslDomainTypes> (model_type)) << ""
		", \"Name\": \"" << std::string (name, name_len) << "\""
		", \"NameLen\": " << name_len << ""
		", \"AttribInfoInUpdates\": " << (use_attribinfo_in_updates ? "true" : "false") << ""
		", \"StatusCode\": " << rsslStateCodeToString (status_code) << ""
		" }";

/* 7.5.9.2 Set the message model type of the response. */
	response.msgBase.domainType = model_type;
/* 7.5.9.3 Set response type. */
	response.msgBase.msgClass = RSSL_MC_STATUS;
/* No payload. */
	response.msgBase.containerType = RSSL_DT_NO_DATA;
/* Set the request token. */
	response.msgBase.streamId = request_token;

/* RDM 6.2.3 AttribInfo
 * if the ReqMsg set AttribInfoInUpdates, then the AttribInfo must be provided for all
 * Refresh, Status, and Update RespMsgs.
 */
	if (use_attribinfo_in_updates) {
		response.msgBase.msgKey.serviceId   = service_id;
		response.msgBase.msgKey.nameType    = RDM_INSTRUMENT_NAME_TYPE_RIC;
		response.msgBase.msgKey.name.data   = const_cast<char*> (name);
		response.msgBase.msgKey.name.length = static_cast<uint32_t> (name_len);
		response.msgBase.msgKey.flags = RSSL_MKF_HAS_SERVICE_ID | RSSL_MKF_HAS_NAME_TYPE | RSSL_MKF_HAS_NAME;
		response.flags |= RSSL_STMF_HAS_MSG_KEY;
	}
	
/* Item interaction state. */
	response.state.streamState = RSSL_STREAM_CLOSED;
/* Data quality state. */
	response.state.dataState = RSSL_DATA_OK;
/* Error code. */
	response.state.code = status_code;
	response.flags |= RSSL_STMF_HAS_STATE;

	buf = rsslGetBuffer (handle_, MAX_MSG_SIZE, RSSL_FALSE /* not packed */, &rssl_err);
	if (nullptr == buf) {
		LOG(ERROR) << prefix_ << "rsslGetBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			", \"size\": " << MAX_MSG_SIZE << ""
			", \"packedBuffer\": false"
			" }";
		return false;
	}
	rc = rsslSetEncodeIteratorBuffer (&it, buf);
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorBuffer: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	rc = rsslSetEncodeIteratorRWFVersion (&it, GetRwfMajorVersion(), GetRwfMinorVersion());
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslSetEncodeIteratorRWFVersion: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			", \"majorVersion\": " << static_cast<unsigned> (GetRwfMajorVersion()) << ""
			", \"minorVersion\": " << static_cast<unsigned> (GetRwfMinorVersion()) << ""
			" }";
		goto cleanup;
	}
	rc = rsslEncodeMsg (&it, reinterpret_cast<RsslMsg*> (&response));
	if (RSSL_RET_SUCCESS != rc) {
		LOG(ERROR) << prefix_ << "rsslEncodeMsg: { "
			  "\"returnCode\": " << static_cast<signed> (rc) << ""
			", \"enumeration\": \"" << rsslRetCodeToString (rc) << "\""
			", \"text\": \"" << rsslRetCodeInfo (rc) << "\""
			" }";
		goto cleanup;
	}
	buf->length = rsslGetEncodedBufferLength (&it);
	LOG_IF(WARNING, 0 == buf->length) << prefix_ << "rsslGetEncodedBufferLength returned 0.";

	if (DCHECK_IS_ON()) {
/* Message validation. */
		if (!rsslValidateMsg (reinterpret_cast<RsslMsg*> (&response))) {
			cumulative_stats_[CLIENT_PC_ITEM_CLOSE_MALFORMED]++;
			LOG(ERROR) << prefix_ << "rsslValidateMsg failed.";
			goto cleanup;
		} else {
			cumulative_stats_[CLIENT_PC_ITEM_CLOSE_VALIDATED]++;
			LOG(INFO) << prefix_ << "rsslValidateMsg succeeded.";
		}
	}

	if (!Submit (buf)) {
		goto cleanup;
	}
	cumulative_stats_[CLIENT_PC_ITEM_CLOSED]++;
	return true;
cleanup:
	if (RSSL_RET_SUCCESS != rsslReleaseBuffer (buf, &rssl_err)) {
		LOG(WARNING) << prefix_ << "rsslReleaseBuffer: { "
			  "\"rsslErrorId\": " << rssl_err.rsslErrorId << ""
			", \"sysError\": " << rssl_err.sysError << ""
			", \"text\": \"" << rssl_err.text << "\""
			" }";
	}
	return false;
}

/* Forward submit requests to containing provider.
 */
int
anaguma::client_t::Submit (
	RsslBuffer* buf
	)
{
	const int status = provider_->Submit (handle_, buf);
	if (status) cumulative_stats_[CLIENT_PC_UPA_MSGS_SENT]++;
	return status;
}

/* eof */
