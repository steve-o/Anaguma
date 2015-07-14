/* RFA provider client session.
 */

#include "client.hh"

#include <algorithm>
#include <utility>

#include <windows.h>

#include "chromium/logging.hh"
#include "chromium/string_piece.hh"
#include "googleurl/url_parse.h"
#include "error.hh"
#include "rfaostream.hh"
#include "provider.hh"
#include "worldbank.hh"

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


using rfa::common::RFA_String;

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
	const rfa::common::Handle* handle,
	const char* address
	) :
	creation_time_ (boost::posix_time::second_clock::universal_time()),
	last_activity_ (creation_time_),
	provider_ (provider),
	address_ (address),
	handle_ (nullptr),
	login_token_ (nullptr),
	rwf_major_version_ (0),
	rwf_minor_version_ (0),
	is_logged_in_ (false)
{
	ZeroMemory (cumulative_stats_, sizeof (cumulative_stats_));
	ZeroMemory (snap_stats_, sizeof (snap_stats_));

/* Set logger ID */
	std::ostringstream ss;
	ss << handle << ':';
	prefix_.assign (ss.str());
}

anaguma::client_t::~client_t()
{
	using namespace boost::posix_time;
	const auto uptime = second_clock::universal_time() - creation_time_;
	VLOG(3) << prefix_ << "Summary: {"
		 " \"Uptime\": \"" << to_simple_string (uptime) << "\""
		", \"RfaEventsReceived\": " << cumulative_stats_[CLIENT_PC_RFA_EVENTS_RECEIVED] <<
		", \"RfaMessagesSent\": " << cumulative_stats_[CLIENT_PC_RFA_MSGS_SENT] <<
		" }";
}

bool
anaguma::client_t::Init (
	rfa::common::Handle*const handle
	)
{
/* save non-const client session handle. */
	handle_ = handle;
	return true;
}

bool
anaguma::client_t::GetAssociatedMetaInfo()
{
	DCHECK(nullptr != handle_);

	last_activity_ = boost::posix_time::second_clock::universal_time();

/* Store negotiated Reuters Wire Format version information. */
	auto& map = provider_->map_;
	map.setAssociatedMetaInfo (*handle_);
	rwf_major_version_ = map.getMajorVersion();
	rwf_minor_version_ = map.getMinorVersion();
	LOG(INFO) << prefix_ <<
		"RWF: { "
		  "\"MajorVersion\": " << (unsigned)GetRwfMajorVersion() <<
		", \"MinorVersion\": " << (unsigned)GetRwfMinorVersion() <<
		" }";
	return true;
}

/* RFA callback entry point.
 */
void
anaguma::client_t::processEvent (
	const rfa::common::Event& event_
	)
{
	VLOG(1) << event_;
	cumulative_stats_[CLIENT_PC_RFA_EVENTS_RECEIVED]++;
	last_activity_ = boost::posix_time::second_clock::universal_time();
	switch (event_.getType()) {
	case rfa::sessionLayer::OMMSolicitedItemEventEnum:
		OnOMMSolicitedItemEvent (static_cast<const rfa::sessionLayer::OMMSolicitedItemEvent&>(event_));
		break;

	case rfa::sessionLayer::OMMInactiveClientSessionEventEnum:
		OnOMMInactiveClientSessionEvent(static_cast<const rfa::sessionLayer::OMMInactiveClientSessionEvent&>(event_));
		break;

        default:
		cumulative_stats_[CLIENT_PC_RFA_EVENTS_DISCARDED]++;
		LOG(WARNING) << prefix_ << "Uncaught: " << event_;
                break;
        }
}

/* 7.4.7.2 Handling consumer solicited item events.
 */
void
anaguma::client_t::OnOMMSolicitedItemEvent (
	const rfa::sessionLayer::OMMSolicitedItemEvent&	item_event
	)
{
	cumulative_stats_[CLIENT_PC_OMM_SOLICITED_ITEM_EVENTS_RECEIVED]++;
	const rfa::common::Msg& msg = item_event.getMsg();

	if (msg.isBlank()) {
		cumulative_stats_[CLIENT_PC_OMM_SOLICITED_ITEM_EVENTS_DISCARDED]++;
		LOG(WARNING) << prefix_ << "Discarding blank solicited message: " << msg;
		return;
	}

	switch (msg.getMsgType()) {
	case rfa::message::ReqMsgEnum:
		OnReqMsg (static_cast<const rfa::message::ReqMsg&>(msg), &(item_event.getRequestToken()));
		break;
	default:
		cumulative_stats_[CLIENT_PC_OMM_SOLICITED_ITEM_EVENTS_DISCARDED]++;
		LOG(WARNING) << prefix_ << "Uncaught solicited message: " << msg;
		break;
	}
}

void
anaguma::client_t::OnReqMsg (
	const rfa::message::ReqMsg& request_msg,
	rfa::sessionLayer::RequestToken*const request_token
	)
{
	cumulative_stats_[CLIENT_PC_REQUEST_MSGS_RECEIVED]++;
	switch (request_msg.getMsgModelType()) {
	case rfa::rdm::MMT_LOGIN:
		OnLoginRequest (request_msg, request_token);
		break;
	case rfa::rdm::MMT_DIRECTORY:
		OnDirectoryRequest (request_msg, request_token);
		break;
	case rfa::rdm::MMT_DICTIONARY:
		OnDictionaryRequest (request_msg, request_token);
		break;
	case rfa::rdm::MMT_MARKET_PRICE:
	case rfa::rdm::MMT_MARKET_BY_ORDER:
	case rfa::rdm::MMT_MARKET_BY_PRICE:
	case rfa::rdm::MMT_MARKET_MAKER:
	case rfa::rdm::MMT_SYMBOL_LIST:
		OnItemRequest (request_msg, request_token);
		break;
	default:
		cumulative_stats_[CLIENT_PC_REQUEST_MSGS_DISCARDED]++;
		LOG(WARNING) << prefix_ << "Uncaught: " << request_msg;
		break;
	}
}

/* The message model type MMT_LOGIN represents a login request. Specific
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
void
anaguma::client_t::OnLoginRequest (
	const rfa::message::ReqMsg& login_msg,
	rfa::sessionLayer::RequestToken*const login_token
	)
{
	cumulative_stats_[CLIENT_PC_MMT_LOGIN_RECEIVED]++;
/* Pass through RFA validation and report exceptions */
	uint8_t validation_status = rfa::message::MsgValidationError;
	try {
/* 4.2.8 Message Validation. */
		RFA_String warningText;
		validation_status = login_msg.validateMsg (&warningText);
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_VALIDATED]++;
		if (rfa::message::MsgValidationWarning == validation_status)
			LOG(WARNING) << prefix_ << "MMT_LOGIN::validateMsg: { \"warningText\": \"" << warningText << "\" }";
	} catch (const rfa::common::InvalidUsageException& e) {
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_MALFORMED]++;
		LOG(WARNING) << prefix_ <<
			"MMT_LOGIN::InvalidUsageException: { " <<
			  "\"StatusText\": \"" << e.getStatus().getStatusText() << "\""
			", " << login_msg <<
			", \"RequestToken\": " << login_token <<
			" }";
	} catch (const std::exception& e) {
		LOG(ERROR) << prefix_ << "Rfa::Exception: { "
			"\"What\": \"" << e.what() << "\" }";
	}

	static const uint8_t streaming_request = rfa::message::ReqMsg::InitialImageFlag | rfa::message::ReqMsg::InterestAfterRefreshFlag;
	static const uint8_t pause_request     = rfa::message::ReqMsg::PauseFlag;

	try {
/* Reject on RFA validation failing. */
		if (rfa::message::MsgValidationError == validation_status) 
		{
			LOG(WARNING) << prefix_ << "Rejecting MMT_LOGIN as RFA validation failed.";
			RejectLogin (login_msg, login_token);
			return;
		}

		const bool is_streaming_request = ((login_msg.getInteractionType() == streaming_request)
						|| (login_msg.getInteractionType() == (streaming_request | pause_request)));
		const bool is_pause_request     = (login_msg.getInteractionType() == pause_request);

/* RDM 3.2.4: All message types except GenericMsg should include an AttribInfo.
 * RFA example code verifies existence of AttribInfo with an assertion.
 */
		const bool has_attribinfo = (0 != (login_msg.getHintMask() & rfa::message::ReqMsg::AttribInfoFlag));
		const bool has_name = has_attribinfo && (rfa::message::AttribInfo::NameFlag == (login_msg.getAttribInfo().getHintMask() & rfa::message::AttribInfo::NameFlag));
		const bool has_nametype = has_attribinfo && (rfa::message::AttribInfo::NameTypeFlag == (login_msg.getAttribInfo().getHintMask() & rfa::message::AttribInfo::NameTypeFlag));

/* invalid RDM login. */
		if ((!is_streaming_request && !is_pause_request)
			|| !has_attribinfo
			|| !has_name
			|| !has_nametype)
		{
			cumulative_stats_[CLIENT_PC_MMT_LOGIN_MALFORMED]++;
			LOG(WARNING) << prefix_ << "Rejecting MMT_LOGIN as RDM validation failed: " << login_msg;
			RejectLogin (login_msg, login_token);
		}
		else
		{
			AcceptLogin (login_msg, login_token);

/* save token for closing the session. */
			login_token_ = login_token;
			is_logged_in_ = true;
		}
/* ignore any error */
	} catch (const rfa::common::InvalidUsageException& e) {
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_EXCEPTION]++;
		LOG(ERROR) << prefix_ <<
			"MMT_LOGIN::InvalidUsageException: { "
			   "\"StatusText\": \"" << e.getStatus().getStatusText() << "\""
			", " << login_msg <<
			", \"RequestToken\": " << login_token <<
			" }";
	} catch (const std::exception& e) {
		LOG(ERROR) << prefix_ << "Rfa::Exception: { "
			"\"What\": \"" << e.what() << "\" }";
	}
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
	const rfa::message::ReqMsg& login_msg,
	rfa::sessionLayer::RequestToken*const login_token
	)
{
	VLOG(2) << prefix_ << "Sending MMT_LOGIN rejection.";

/* 7.5.9.1 Create a response message (4.2.2) */
	auto& response = provider_->response_;
	response.clear();
/* 7.5.9.2 Set the message model type of the response. */
	response.setMsgModelType (rfa::rdm::MMT_LOGIN);
/* 7.5.9.3 Set response type.  RDM 3.2.2 RespMsg: Status when rejecting login. */
	response.setRespType (rfa::message::RespMsg::StatusEnum);

/* 7.5.9.5 Create or re-use a request attribute object (4.2.4) */
	auto& attribInfo = provider_->attribInfo_;
	attribInfo.clear();
/* RDM 3.2.4 AttribInfo: Name is required, NameType is recommended: default is USER_NAME (1) */
	attribInfo.setNameType (login_msg.getAttribInfo().getNameType());
	attribInfo.setName (login_msg.getAttribInfo().getName());
	response.setAttribInfo (attribInfo);

	auto& status = provider_->status_;
	status.clear();
/* Item interaction state: RDM 3.2.2 RespMsg: Closed or ClosedRecover. */
	status.setStreamState (rfa::common::RespStatus::ClosedEnum);
/* Data quality state: RDM 3.2.2 RespMsg: Suspect. */
	status.setDataState (rfa::common::RespStatus::SuspectEnum);
/* Error code: RDM 3.4.3 Authentication: NotAuthorized. */
	status.setStatusCode (rfa::common::RespStatus::NotAuthorizedEnum);
	response.setRespStatus (status);

/* 4.2.8 Message Validation.  RFA provides an interface to verify that
 * constructed messages of these types conform to the Reuters Domain
 * Models as specified in RFA API 7 RDM Usage Guide.
 */
	uint8_t validation_status = rfa::message::MsgValidationError;
	try {
		RFA_String warningText;
		validation_status = response.validateMsg (&warningText);
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_RESPONSE_VALIDATED]++;
		if (rfa::message::MsgValidationWarning == validation_status)
			LOG(WARNING) << prefix_ << "MMT_LOGIN::validateMsg: { \"warningText\": \"" << warningText << "\" }";
	} catch (const rfa::common::InvalidUsageException& e) {
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_RESPONSE_MALFORMED]++;
		LOG(ERROR) << prefix_ <<
			"MMT_LOGIN::InvalidUsageException: { " <<
			   "\"StatusText\": \"" << e.getStatus().getStatusText() << "\""
			", " << response <<
			" }";
	} catch (const std::exception& e) {
		LOG(ERROR) << prefix_ << "Rfa::Exception: { "
			"\"What\": \"" << e.what() << "\" }";
	}

	Submit (&response, login_token, nullptr);
	cumulative_stats_[CLIENT_PC_MMT_LOGIN_REJECTED]++;
	return true;
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
	const rfa::message::ReqMsg& login_msg,
	rfa::sessionLayer::RequestToken*const login_token
	)
{
	VLOG(2) << prefix_ << "Sending MMT_LOGIN accepted.";

/* 7.5.9.1 Create a response message (4.2.2) */
	auto& response = provider_->response_;
	response.clear();
/* 7.5.9.2 Set the message model type of the response. */
	response.setMsgModelType (rfa::rdm::MMT_LOGIN);
/* 7.5.9.3 Set response type.  RDM 3.2.2 RespMsg: Refresh when accepting login. */
	response.setRespType (rfa::message::RespMsg::RefreshEnum);
	response.setIndicationMask (rfa::message::RespMsg::RefreshCompleteFlag);

/* 7.5.9.5 Create or re-use a request attribute object (4.2.4) */
	auto& attribInfo = provider_->attribInfo_;
	attribInfo.clear();
/* RDM 3.2.4 AttribInfo: Name is required, NameType is recommended: default is USER_NAME (1) */
	attribInfo.setNameType (login_msg.getAttribInfo().getNameType());
	attribInfo.setName (login_msg.getAttribInfo().getName());

	auto& elementList = provider_->elementList_;
	elementList.setAssociatedMetaInfo (GetRwfMajorVersion(), GetRwfMinorVersion());
/* Clear required for SingleWriteIterator state machine. */
	auto& it = provider_->element_it_;
	DCHECK (it.isInitialized());
	it.clear();
	it.start (elementList);

/* RDM 3.3.2 Login Response Elements */
	rfa::data::ElementEntry entry (false);
/* Reflect back DACS authentication parameters. */
	if (login_msg.getAttribInfo().getHintMask() & rfa::message::AttribInfo::AttribFlag)
	{
/* RDM Table 52: RFA will raise a warning if request & reponse differ. */
	}
/* Images and & updates could be stale. */
	entry.setName (rfa::rdm::ENAME_ALLOW_SUSPECT_DATA);
	it.bind (entry);
	it.setUInt (1);
/* No permission expressions. */
	entry.setName (rfa::rdm::ENAME_PROV_PERM_EXP);
	it.bind (entry);
	it.setUInt (0);
/* No permission profile. */
	entry.setName (rfa::rdm::ENAME_PROV_PERM_PROF);
	it.bind (entry);
	it.setUInt (0);
/* Downstream application drives stream recovery. */
	entry.setName (rfa::rdm::ENAME_SINGLE_OPEN);
	it.bind (entry);
	it.setUInt (0);
/* Batch requests not supported. */
/* OMM posts not supported. */
/* Optimized pause and resume not supported. */
/* Views not supported. */
/* Warm standby not supported. */
/* Binding complete. */
	it.complete();
	attribInfo.setAttrib (elementList);
	response.setAttribInfo (attribInfo);

	auto& status = provider_->status_;
	status.clear();
/* Item interaction state: RDM 3.2.2 RespMsg: Open. */
	status.setStreamState (rfa::common::RespStatus::OpenEnum);
/* Data quality state: RDM 3.2.2 RespMsg: Ok. */
	status.setDataState (rfa::common::RespStatus::OkEnum);
/* Error code: RDM 3.2.2 RespMsg: None. */
	status.setStatusCode (rfa::common::RespStatus::NoneEnum);
	response.setRespStatus (status);

/* 4.2.8 Message Validation.  RFA provides an interface to verify that
 * constructed messages of these types conform to the Reuters Domain
 * Models as specified in RFA API 7 RDM Usage Guide.
 */
	uint8_t validation_status = rfa::message::MsgValidationError;
	try {
		RFA_String warningText;
		validation_status = response.validateMsg (&warningText);
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_RESPONSE_VALIDATED]++;
		if (rfa::message::MsgValidationWarning == validation_status)
			LOG(WARNING) << prefix_ << "MMT_LOGIN::validateMsg: { \"warningText\": \"" << warningText << "\" }";
	} catch (const rfa::common::InvalidUsageException& e) {
		cumulative_stats_[CLIENT_PC_MMT_LOGIN_RESPONSE_MALFORMED]++;
		LOG(ERROR) << prefix_ <<
			"MMT_LOGIN::InvalidUsageException: { " <<
			   "\"StatusText\": \"" << e.getStatus().getStatusText() << "\""
			", " << response <<
			" }";
	} catch (const std::exception& e) {
		LOG(ERROR) << prefix_ << "Rfa::Exception: { "
			"\"What\": \"" << e.what() << "\" }";
	}

	Submit (&response, login_token, nullptr);
	cumulative_stats_[CLIENT_PC_MMT_LOGIN_ACCEPTED]++;
	return true;
}

/* RDM 4.2.1 ReqMsg
 * Streaming request or Nonstreaming request. No special semantics or
 * restrictions. Pause request is not supported.
 */
void
anaguma::client_t::OnDirectoryRequest (
	const rfa::message::ReqMsg& request_msg,
	rfa::sessionLayer::RequestToken*const request_token
	)
{
	cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_REQUEST_RECEIVED]++;
/* Pass through RFA validation and report exceptions */
	uint8_t validation_status = rfa::message::MsgValidationError;
	try {
/* 4.2.8 Message Validation. */
		RFA_String warningText;
		validation_status = request_msg.validateMsg (&warningText);
		cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_REQUEST_VALIDATED]++;
		if (rfa::message::MsgValidationWarning == validation_status)
			LOG(WARNING) << prefix_ << "MMT_DIRECTORY::validateMsg: { \"warningText\": \"" << warningText << "\" }";
	} catch (const rfa::common::InvalidUsageException& e) {
		cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_REQUEST_MALFORMED]++;
		LOG(WARNING) << prefix_ <<
			"MMT_DIRECTORY::InvalidUsageException: { " <<
			  "\"StatusText\": \"" << e.getStatus().getStatusText() << "\""
			", " << request_msg <<
			", \"RequestToken\": " << request_token <<
			" }";
	} catch (const std::exception& e) {
		LOG(ERROR) << prefix_ << "Rfa::Exception: { "
			"\"What\": \"" << e.what() << "\" }";
	}

	static const uint8_t snapshot_request  = rfa::message::ReqMsg::InitialImageFlag;
	static const uint8_t streaming_request = snapshot_request | rfa::message::ReqMsg::InterestAfterRefreshFlag;

	try {
/* Reject on RFA validation failing. */
		if (rfa::message::MsgValidationError == validation_status) 
		{
			LOG(WARNING) << prefix_ << "Discarded MMT_DIRECTORY request as RFA validation failed.";
			return;
		}

/* RDM 4.2.4 AttribInfo required for ReqMsg. */
		const bool has_attribinfo = (0 != (request_msg.getHintMask() & rfa::message::ReqMsg::AttribInfoFlag));

		const bool is_snapshot_request  = (request_msg.getInteractionType() == snapshot_request);
		const bool is_streaming_request = (request_msg.getInteractionType() == streaming_request);

		if ((!is_snapshot_request && !is_streaming_request)
			|| !has_attribinfo)
		{
			cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_MALFORMED]++;
			LOG(WARNING) << prefix_ << "Discarded MMT_DIRECTORY request as RDM validation failed: " << request_msg;
			return;
		}

/* Filtering of directory contents. */
		const bool has_datamask = (0 != (request_msg.getAttribInfo().getHintMask() & rfa::message::AttribInfo::DataMaskFlag));
		const uint32_t filter_mask = has_datamask ? request_msg.getAttribInfo().getDataMask() : UINT32_MAX;
/* Provides ServiceName */
		if (0 != (request_msg.getAttribInfo().getHintMask() & rfa::message::AttribInfo::ServiceNameFlag))
		{
			const char* service_name = request_msg.getAttribInfo().getServiceName().c_str();
			SendDirectoryResponse (request_token, service_name, filter_mask);
		}
/* Provides ServiceID */
		else if (0 != (request_msg.getAttribInfo().getHintMask() & rfa::message::AttribInfo::ServiceIDFlag) &&
			0 != provider_->GetServiceId() /* service id is unknown */)
		{
			const uint32_t service_id = request_msg.getAttribInfo().getServiceID();
			if (service_id == provider_->GetServiceId()) {
				SendDirectoryResponse (request_token, provider_->GetServiceName(), filter_mask);
			} else {
/* default to full directory if id does not match */
				LOG(WARNING) << prefix_ << "Received MMT_DIRECTORY request for unknown service id #" << service_id << ", returning entire directory.";
				SendDirectoryResponse (request_token, nullptr, filter_mask);
			}
		}
/* Provide all services directory. */
		else
		{
			SendDirectoryResponse (request_token, nullptr, filter_mask);
		}
/* ignore any error */
	} catch (const rfa::common::InvalidUsageException& e) {
		cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_EXCEPTION]++;
		LOG(ERROR) << prefix_ << "MMT_DIRECTORY::InvalidUsageException: { "
				"\"StatusText\": \"" << e.getStatus().getStatusText() << "\""
				" }";
	} catch (const std::exception& e) {
		LOG(ERROR) << prefix_ << "Rfa::Exception: { "
			"\"What\": \"" << e.what() << "\" }";
	}
}

void
anaguma::client_t::OnDictionaryRequest (
	const rfa::message::ReqMsg&	request_msg,
	rfa::sessionLayer::RequestToken*const request_token
	)
{
	cumulative_stats_[CLIENT_PC_MMT_DICTIONARY_REQUEST_RECEIVED]++;
	LOG(INFO) << prefix_ << "DictionaryRequest:" << request_msg;
}

void
anaguma::client_t::OnItemRequest (
	const rfa::message::ReqMsg&	request_msg,
	rfa::sessionLayer::RequestToken*const request_token
	)
{
	cumulative_stats_[CLIENT_PC_ITEM_REQUEST_RECEIVED]++;
	LOG(INFO) << prefix_ << "ItemRequest:" << request_msg;

/* 10.3.6 Handling Item Requests
 * - Ensure that the requesting session is logged in.
 * - Determine whether the requested QoS can be satisified.
 * - Ensure that the same stream is not already provisioned.
 */
	static const uint8_t streaming_request = rfa::message::ReqMsg::InitialImageFlag | rfa::message::ReqMsg::InterestAfterRefreshFlag;
	static const uint8_t snapshot_request  = rfa::message::ReqMsg::InitialImageFlag;
	static const uint8_t pause_request     = rfa::message::ReqMsg::PauseFlag;
	static const uint8_t resume_request    = rfa::message::ReqMsg::InterestAfterRefreshFlag;
	static const uint8_t close_request     = 0;

/* A response is not required to be immediately generated, for example
 * forwarding the clients request to an upstream resource and waiting for
 * a reply.
 */
	try {
		const uint32_t service_id    = request_msg.getAttribInfo().getServiceID();
		const uint8_t  model_type    = request_msg.getMsgModelType();
		const char*    item_name     = request_msg.getAttribInfo().getName().c_str();
		const size_t   item_name_len = request_msg.getAttribInfo().getName().size();
		const bool use_attribinfo_in_updates = (0 != (request_msg.getIndicationMask() & rfa::message::ReqMsg::AttribInfoInUpdatesFlag));

		if (!is_logged_in_) {
			cumulative_stats_[CLIENT_PC_ITEM_REQUEST_REJECTED]++;
			LOG(INFO) << prefix_ << "Closing request for client without accepted login.";
			SendClose (request_token, service_id, model_type, item_name, use_attribinfo_in_updates, rfa::common::RespStatus::NotAuthorizedEnum);
			return;
		}

/* Only accept MMT_MARKET_PRICE. */
		if (rfa::rdm::MMT_MARKET_PRICE != model_type)
		{
			cumulative_stats_[CLIENT_PC_ITEM_REQUEST_MALFORMED]++;
			LOG(INFO) << prefix_ << "Closing request for unsupported message model type.";
			SendClose (request_token, service_id, model_type, item_name, use_attribinfo_in_updates, rfa::common::RespStatus::NotAuthorizedEnum);
			return;
		}

		const bool is_streaming_request = (request_msg.getInteractionType() == streaming_request);
/* 7.4.3.2 Request Tokens
 * Providers should not attempt to submit data after the provider has received a close request for an item. */
		const bool is_close             = (request_msg.getInteractionType() == close_request);

/* capture ServiceID */
		if (0 == provider_->GetServiceId() &&
		    0 == request_msg.getAttribInfo().getServiceName().compareCase (provider_->GetServiceName()))
		{
			LOG(INFO) << prefix_ << "Detected service id #" << service_id << " for \"" << provider_->GetServiceName() << "\".";
			provider_->SetServiceId (service_id);
		}

		if (is_close)
		{
			if (!provider_->RemoveRequest (request_token))
			{
				cumulative_stats_[CLIENT_PC_ITEM_REQUEST_DISCARDED]++;
				LOG(INFO) << prefix_ << "Discarding close request on closed item.";
			}
			else
			{		
				cumulative_stats_[CLIENT_PC_ITEM_CLOSED]++;
				DLOG(INFO) << prefix_ << "Closing open request.";
			}
		}
		else if (is_streaming_request)
		{
			OnItemStreamingRequest (request_msg, request_token);
		}
		else
		{
			OnItemSnapshotRequest (request_msg, request_token);
		}

/* ignore any error */
	} catch (const rfa::common::InvalidUsageException& e) {
		cumulative_stats_[CLIENT_PC_ITEM_EXCEPTION]++;
		LOG(ERROR) << prefix_ << "InvalidUsageException: { "
				   "\"StatusText\": \"" << e.getStatus().getStatusText() << "\"" <<
				", " << request_msg <<
				", \"RequestToken\": " << request_token <<
				" }";
	} catch (const std::exception& e) {
		LOG(ERROR) << prefix_ << "Rfa::Exception: { "
			"\"What\": \"" << e.what() << "\""
			" }";
	}
}

void
anaguma::client_t::OnItemSnapshotRequest (
	const rfa::message::ReqMsg&	request_msg,
	rfa::sessionLayer::RequestToken*const request_token
	)
{
	const uint32_t service_id    = request_msg.getAttribInfo().getServiceID();
	const uint8_t  model_type    = request_msg.getMsgModelType();
	const char*    item_name     = request_msg.getAttribInfo().getName().c_str();
	const bool use_attribinfo_in_updates = (0 != (request_msg.getIndicationMask() & rfa::message::ReqMsg::AttribInfoInUpdatesFlag));

/* closest equivalent to not-supported is NotAuthorizedEnum. */
	cumulative_stats_[CLIENT_PC_ITEM_REQUEST_REJECTED]++;
	LOG(INFO) << prefix_ << "Rejecting unsupported snapshot request.";
	SendClose (request_token, service_id, model_type, item_name, use_attribinfo_in_updates, rfa::common::RespStatus::NotAuthorizedEnum);
}

void
anaguma::client_t::OnItemStreamingRequest (
	const rfa::message::ReqMsg&	request_msg,
	rfa::sessionLayer::RequestToken*const request_token
	)
{
	const uint32_t service_id    = request_msg.getAttribInfo().getServiceID();
	const uint8_t  model_type    = request_msg.getMsgModelType();
	const char*    item_name     = request_msg.getAttribInfo().getName().c_str();
	const size_t   item_name_len = request_msg.getAttribInfo().getName().size();
	const bool use_attribinfo_in_updates = (0 != (request_msg.getIndicationMask() & rfa::message::ReqMsg::AttribInfoInUpdatesFlag));

/* decompose request */
	DVLOG(4) << prefix_ << "item name: [" << item_name << "] len: " << item_name_len;
	url_parse::Parsed parsed;
	url_parse::Component file_name;
	url_.assign ("vta://localhost");
	url_.append (item_name, item_name_len);
	url_parse::ParseStandardURL (url_.c_str(), static_cast<int>(url_.size()), &parsed);
	if (parsed.path.is_valid())
		url_parse::ExtractFileName (url_.c_str(), parsed.path, &file_name);
	if (!file_name.is_valid()) {
		cumulative_stats_[CLIENT_PC_ITEM_REQUEST_MALFORMED]++;
		cumulative_stats_[CLIENT_PC_ITEM_REQUEST_REJECTED]++;
		LOG(INFO) << prefix_ << "Closing invalid request for \"" << item_name << "\"";
		SendClose (request_token, service_id, model_type, item_name, use_attribinfo_in_updates, rfa::common::RespStatus::NotFoundEnum);
		return;
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
		SendInitial (service_id,
			     request_msg.getAttribInfo().getName(), timestamp,
			     rwf_major_version_,
			     rwf_minor_version_,
			     request_token);
/* wait for close */
	}
	else
	{
/* Reissue request for secondary subscribers */
		SendInitial (service_id,
			     request_msg.getAttribInfo().getName(), timestamp,
			     rwf_major_version_,
			     rwf_minor_version_,
			     request_token);
	}
}

/* Initial images and refresh images for reissue requests.
 */
bool
anaguma::client_t::SendInitial (
	uint32_t service_id,
	const RFA_String& stream_name,
	const boost::posix_time::ptime& timestamp,
	uint8_t rwf_major_version,
	uint8_t rwf_minor_version,
	rfa::sessionLayer::RequestToken*const token
	)
{
/* 7.4.8.1 Create a response message (4.2.2) */
	auto& respmsg_ = provider_->response_;
	respmsg_.clear();

/* 7.4.8.2 Create or re-use a request attribute object (4.2.4) */
	auto& attribInfo_ = provider_->attribInfo_;
	attribInfo_.clear();
	attribInfo_.setNameType (rfa::rdm::INSTRUMENT_NAME_RIC);
	attribInfo_.setServiceID (service_id);
	attribInfo_.setName (stream_name);
	respmsg_.setAttribInfo (attribInfo_);

/* 7.4.8.3 Set the message model type of the response. */
	respmsg_.setMsgModelType (rfa::rdm::MMT_MARKET_PRICE);
/* 7.4.8.4 Set response type, response type number, and indication mask. */
	respmsg_.setRespType (rfa::message::RespMsg::RefreshEnum);

/* for snapshot images do not cache */
	respmsg_.setIndicationMask (rfa::message::RespMsg::DoNotFilterFlag     |
				    rfa::message::RespMsg::RefreshCompleteFlag |
				    rfa::message::RespMsg::DoNotRippleFlag     |
				    rfa::message::RespMsg::DoNotCacheFlag);
/* 4.3.1 RespMsg.Payload */
// not std::map :(  derived from rfa::common::Data
	auto& fields_ = provider_->fields_;
	fields_.setAssociatedMetaInfo (rwf_major_version, rwf_minor_version);

/* TIMEACT & ACTIV_DATE */
	struct tm _tm;
	__time32_t time32 = to_unix_epoch<__time32_t> (timestamp);
	_gmtime32_s (&_tm, &time32);

/* Clear required for SingleWriteIterator state machine. */
	auto& it = provider_->field_it_;
	DCHECK (it.isInitialized());
	it.clear();
	it.start (fields_);

/* For each field set the Id via a FieldEntry bound to the iterator followed by setting the data.
 * The iterator API provides setters for common types excluding 32-bit floats, with fallback to 
 * a generic DataBuffer API for other types or support of pre-calculated values.
 */
	rfa::data::FieldEntry field (false);
/* PROD_PERM */
	field.setFieldID (kRdmProductPermissionId);
	it.bind (field);
	const uint64_t prod_perm = 213;		/* for JPY= */
	it.setUInt (prod_perm);

/* PREF_DISP */
	field.setFieldID (kRdmPreferredDisplayTemplateId);
	it.bind (field);
	const uint32_t pref_disp = 6205;	/* for JPY= */
	it.setUInt (pref_disp);

/* BKGD_REF */
	field.setFieldID (kRdmBackroundReferenceId);
	it.bind (field);
	const RFA_String bkgd_ref ("Japanese Yen", 0, false);
	it.setString (bkgd_ref, rfa::data::DataBuffer::StringAsciiEnum);

/* GV1_TEXT */
	field.setFieldID (kRdmGeneralText1Id);
	it.bind (field);
	const RFA_String gv1_text ("SPOT", 0, false);
	it.setString (gv1_text, rfa::data::DataBuffer::StringRMTESEnum);

/* GV2_TEXT */
	field.setFieldID (kRdmGeneralText2Id);
	it.bind (field);
	const RFA_String gv2_text ("USDJPY", 0, false);
	it.setString (gv2_text, rfa::data::DataBuffer::StringRMTESEnum);

/* PRIMACT_1 */
	field.setFieldID (kRdmPrimaryActivity1Id);
	it.bind (field);
	const double bid = 82.20;
	it.setReal (worldbank::mantissa (bid), rfa::data::ExponentNeg2);

/* SEC_ACT_1 */
	field.setFieldID (kRdmSecondActivity1Id);
	it.bind (field);
	const double ask = 82.22;
	it.setReal (worldbank::mantissa (ask), rfa::data::ExponentNeg2);

/* CTBTR_1 */
	field.setFieldID (kRdmContributor1Id);
	it.bind (field);
	const RFA_String ctbtr_1 ("RBS", 0, false);
	it.setString (ctbtr_1, rfa::data::DataBuffer::StringRMTESEnum);

/* CTB_LOC1 */
	field.setFieldID (kRdmContributorLocation1Id);
	it.bind (field);
	const RFA_String ctb_loc1 ("XST", 0, false);
	it.setString (ctb_loc1, rfa::data::DataBuffer::StringRMTESEnum);

/* CTB_PAGE1 */
	field.setFieldID (kRdmContributorPage1Id);
	it.bind (field);
	const RFA_String ctb_page1 ("1RBS", 0, false);
	it.setString (ctb_page1, rfa::data::DataBuffer::StringRMTESEnum);

/* DLG_CODE1 */
	field.setFieldID (kRdmDealingCode1Id);
	it.bind (field);
	const RFA_String dlg_code1 ("RBSN", 0, false);
	it.setString (dlg_code1, rfa::data::DataBuffer::StringRMTESEnum);

/* VALUE_TS1 */
	field.setFieldID (kRdmActivityTime1Id);
	it.bind (field);
	it.setTime (_tm.tm_hour, _tm.tm_min, _tm.tm_sec, 0 /* ms */);

/* VALUE_DT1 */
	field.setFieldID (kRdmActivityDate1Id);
	it.bind (field);
	const uint16_t year  = /* rfa(yyyy) */ 1900 + _tm.tm_year /* tm(yyyy-1900 */;
	const uint8_t  month = /* rfa(1-12) */    1 + _tm.tm_mon  /* tm(0-11) */;
	const uint8_t  day   = /* rfa(1-31) */        _tm.tm_mday /* tm(1-31) */;
	it.setDate (year, month, day);

	it.complete();
	respmsg_.setPayload (fields_);

/** Optional: but require to replace stale values in cache when stale values are supported. **/
	auto& status_ = provider_->status_;
	status_.clear();
/* Item interaction state: Open, Closed, ClosedRecover, Redirected, NonStreaming, or Unspecified. */
	status_.setStreamState (rfa::common::RespStatus::OpenEnum);
/* Data quality state: Ok, Suspect, or Unspecified. */
	status_.setDataState (rfa::common::RespStatus::OkEnum);
/* Error code, e.g. NotFound, InvalidArgument, ... */
	status_.setStatusCode (rfa::common::RespStatus::NoneEnum);
	respmsg_.setRespStatus (status_);

	if (DCHECK_IS_ON()) {
/* 4.2.8 Message Validation.  RFA provides an interface to verify that
 * constructed messages of these types conform to the Reuters Domain
 * Models as specified in RFA API 7 RDM Usage Guide.
 */
		uint8_t validation_status = rfa::message::MsgValidationError;
		try {
			RFA_String warningText;
			validation_status = respmsg_.validateMsg (&warningText);
			if (rfa::message::MsgValidationWarning == validation_status)
				LOG(ERROR) << prefix_ << "validateMsg: { \"warningText\": \"" << warningText << "\" }";
		} catch (const rfa::common::InvalidUsageException& e) {
			LOG(ERROR) << prefix_ << "InvalidUsageException: { " <<
					   "\"StatusText\": \"" << e.getStatus().getStatusText() << "\""
					", " << respmsg_ <<
				      " }";
		} catch (const std::exception& e) {
			LOG(ERROR) << prefix_<< "Rfa::Exception: { "
				"\"What\": \"" << e.what() << "\" }";
		}
	}

	Submit (&respmsg_, token, nullptr);	
	cumulative_stats_[CLIENT_PC_ITEM_SENT]++;
	return true;
}

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
	} catch (const rfa::common::InvalidUsageException& e) {
		cumulative_stats_[CLIENT_PC_OMM_INACTIVE_CLIENT_SESSION_EXCEPTION]++;
		LOG(ERROR) << prefix_ << "OMMInactiveClientSession::InvalidUsageException: { "
				"\"StatusText\": \"" << e.getStatus().getStatusText() << "\""
				" }";
	} catch (const std::exception& e) {
		LOG(ERROR) << prefix_ << "Rfa::Exception: { "
			"\"What\": \"" << e.what() << "\" }";
	}
}

/* 10.3.4 Providing Service Directory (Interactive)
 * A Consumer typically requests a Directory from a Provider to retrieve
 * information about available services and their capabilities, and it is the
 * responsibility of the Provider to encode and supply the directory.
 */
bool
anaguma::client_t::SendDirectoryResponse (
	rfa::sessionLayer::RequestToken*const request_token,
	const char* service_name,
	uint32_t filter_mask
	)
{
	VLOG(2) << prefix_ << "Sending directory response.";

/* 7.5.9.1 Create a response message (4.2.2) */
	auto& response = provider_->response_;
	response.clear();
	provider_->GetDirectoryResponse (&response, GetRwfMajorVersion(), GetRwfMinorVersion(), service_name, filter_mask, rfa::rdm::REFRESH_SOLICITED);

/* 4.2.8 Message Validation.  RFA provides an interface to verify that
 * constructed messages of these types conform to the Reuters Domain
 * Models as specified in RFA API 7 RDM Usage Guide.
 */
	uint8_t validation_status = rfa::message::MsgValidationError;
	try { 
		RFA_String warningText;
		validation_status = response.validateMsg (&warningText);
		cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_VALIDATED]++;
		if (rfa::message::MsgValidationWarning == validation_status)
			LOG(ERROR) << prefix_ << "MMT_DIRECTORY::validateMsg: { \"warningText\": \"" << warningText << "\" }";
	} catch (const rfa::common::InvalidUsageException& e) {
		cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_MALFORMED]++;
		LOG(ERROR) << prefix_ <<
			"MMT_DIRECTORY::InvalidUsageException: { " <<
			   "\"StatusText\": \"" << e.getStatus().getStatusText() << "\""
			", " << response <<
			" }";
	} catch (const std::exception& e) {
		LOG(ERROR) << prefix_ << "Rfa::Exception: { "
			"\"What\": \"" << e.what() << "\" }";
	}

/* Create and throw away first token for MMT_DIRECTORY. */
	Submit (&response, request_token, nullptr);
	cumulative_stats_[CLIENT_PC_MMT_DIRECTORY_SENT]++;
	return true;
}

bool
anaguma::client_t::SendClose (
	rfa::sessionLayer::RequestToken*const request_token,
	uint32_t service_id,
	uint8_t model_type,
	const char* name_c,
	bool use_attribinfo_in_updates,
	uint8_t status_code
	)
{
	VLOG(2) << prefix_ << "Sending item close { "
		  "\"RequestToken\": " << request_token <<
		", \"ServiceID\": " << service_id <<
		", \"MsgModelType\": " << (int)model_type <<
		", \"Name\": \"" << name_c << "\""
		", \"AttribInfoInUpdates\": " << (use_attribinfo_in_updates ? "true" : "false") <<
		", \"StatusCode\": " << (int)status_code <<
		" }";
/* 7.5.9.1 Create a response message (4.2.2) */
	auto& response = provider_->response_;
	response.clear();
/* 7.5.9.2 Set the message model type of the response. */
	response.setMsgModelType (model_type);
/* 7.5.9.3 Set response type. */
	response.setRespType (rfa::message::RespMsg::StatusEnum);

/* RDM 6.2.3 AttribInfo
 * if the ReqMsg set AttribInfoInUpdates, then the AttribInfo must be provided for all
 * Refresh, Status, and Update RespMsgs.
 */
	if (use_attribinfo_in_updates) {
/* 7.5.9.5 Create or re-use a request attribute object (4.2.4) */
		auto& attribInfo = provider_->attribInfo_;
		attribInfo.clear();
		attribInfo.setNameType (rfa::rdm::INSTRUMENT_NAME_RIC);
		const RFA_String name (name_c, 0, false);	/* reference */
		attribInfo.setServiceID (service_id);
		attribInfo.setName (name);
		response.setAttribInfo (attribInfo);
	}
	
	auto& status = provider_->status_;
	status.clear();
/* Item interaction state: Open, Closed, ClosedRecover, Redirected, NonStreaming, or Unspecified. */
	status.setStreamState (rfa::common::RespStatus::ClosedEnum);
/* Data quality state: Ok, Suspect, or Unspecified. */
	status.setDataState (rfa::common::RespStatus::OkEnum);
/* Error code, e.g. NotFound, InvalidArgument, ... */
	status.setStatusCode (rfa::common::RespStatus::NotFoundEnum);
	response.setRespStatus (status);

	if (DCHECK_IS_ON()) {
/* 4.2.8 Message Validation.  RFA provides an interface to verify that
 * constructed messages of these types conform to the Reuters Domain
 * Models as specified in RFA API 7 RDM Usage Guide.
 */
		uint8_t validation_status = rfa::message::MsgValidationError;
		try {
			RFA_String warningText;
			validation_status = response.validateMsg (&warningText);
			cumulative_stats_[CLIENT_PC_ITEM_VALIDATED]++;
			if (rfa::message::MsgValidationWarning == validation_status)
				LOG(ERROR) << prefix_ << "validateMsg: { \"warningText\": \"" << warningText << "\" }";
		} catch (const rfa::common::InvalidUsageException& e) {
			cumulative_stats_[CLIENT_PC_ITEM_MALFORMED]++;
			LOG(ERROR) << prefix_ <<
				"InvalidUsageException: { " <<
				   "\"StatusText\": \"" << e.getStatus().getStatusText() << "\""
				", " << response <<
				" }";
		} catch (const std::exception& e) {
			LOG(ERROR) << prefix_ << "Rfa::Exception: { "
				"\"What\": \"" << e.what() << "\" }";
		}
	}

	Submit (&response, request_token, nullptr);	
	cumulative_stats_[CLIENT_PC_ITEM_CLOSED]++;
	return true;
}

/* Forward submit requests to containing provider.
 */
uint32_t
anaguma::client_t::Submit (
	rfa::message::RespMsg*const response,
	rfa::sessionLayer::RequestToken*const token,
	void* closure
	)
{
	return provider_->Submit (static_cast<rfa::common::Msg*const> (response), token, closure);
}

/* eof */