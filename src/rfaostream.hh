/* RFA output streaming.
 */

#ifndef __RFA_OSTREAM_HH__
#define __RFA_OSTREAM_HH__
#pragma once

/* RFA 7.2 */
#include <rfa/rfa.hh>

namespace rfa {
namespace common {

inline
std::ostream& operator<< (std::ostream& o, const RFA_String& rfa_string) {
	o << rfa_string.c_str();
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const rfa::message::AttribInfo& attribInfo) {
	std::ostringstream hint_mask;
	using namespace message;
	if (attribInfo.getHintMask() & AttribInfo::DataMaskFlag)
		hint_mask << "DataMaskFlag";
	if (attribInfo.getHintMask() & AttribInfo::NameFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "NameFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::NameTypeFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "NameTypeFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::ServiceNameFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "ServiceNameFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::IDFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "IDFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::AttribFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "AttribFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::ServiceIDFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "ServiceIDFlag";
	}
	o << "\"AttribInfo\": { "
		  "\"HintMask\": \"" << hint_mask.str() << "\""
		", \"ID\": " << attribInfo.getID() <<
		", \"Name\": \"" << attribInfo.getName() << "\""
/** Serialize value as enumeration not defined **/
		", \"NameType\": " << (int)attribInfo.getNameType() << ""
		", \"ServiceID\": " << attribInfo.getServiceID() <<
		", \"ServiceName\": \"" << attribInfo.getServiceName() << "\""
		" }";
	return o;
}

namespace internal {
class LoginAttribInfo {
	const rfa::message::AttribInfo& attribInfo_;
public:
	LoginAttribInfo (const rfa::message::AttribInfo& attribInfo) :
		attribInfo_ (attribInfo)
	{
	}
	const rfa::message::AttribInfo& getAttribInfo() const
	{
		return attribInfo_;
	}
};

inline
std::ostream& operator<< (std::ostream& o, const LoginAttribInfo& wrapper) {
	const rfa::message::AttribInfo& attribInfo (wrapper.getAttribInfo());
	const char* name_type = "(Unknown)";
	std::ostringstream hint_mask;
	using namespace rfa::message;
	if (attribInfo.getHintMask() & AttribInfo::DataMaskFlag)
		hint_mask << "DataMaskFlag";
	if (attribInfo.getHintMask() & AttribInfo::NameFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "NameFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::NameTypeFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "NameTypeFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::ServiceNameFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "ServiceNameFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::IDFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "IDFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::AttribFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "AttribFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::ServiceIDFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "ServiceIDFlag";
	}
/** type B **/
	switch (attribInfo.getNameType()) {
	case rdm::USER_NAME:			name_type = "USER_NAME"; break;
	case rdm::USER_EMAIL_ADDRESS:		name_type = "USER_EMAIL_ADDRESS"; break;
	case rdm::USER_TOKEN:			name_type = "USER_TOKEN"; break;
	}
	o << "\"AttribInfo\": { "
		  "\"HintMask\": \"" << hint_mask.str() << "\""
		", \"ID\": " << attribInfo.getID() <<
		", \"Name\": \"" << attribInfo.getName() << "\""
		", \"NameType\": \"" << name_type << "\""
		", \"ServiceID\": " << attribInfo.getServiceID() <<
		", \"ServiceName\": \"" << attribInfo.getServiceName() << "\""
		" }";
	return o;
}
class InstrumentAttribInfo {
	const rfa::message::AttribInfo& attribInfo_;
public:
	InstrumentAttribInfo (const rfa::message::AttribInfo& attribInfo) :
		attribInfo_ (attribInfo)
	{
	}
	const rfa::message::AttribInfo& getAttribInfo() const
	{
		return attribInfo_;
	}
};

inline
std::ostream& operator<< (std::ostream& o, const InstrumentAttribInfo& wrapper) {
	const rfa::message::AttribInfo& attribInfo (wrapper.getAttribInfo());
	const char* name_type = "(Unknown)";
	std::ostringstream hint_mask;
	using namespace rfa::message;
	if (attribInfo.getHintMask() & AttribInfo::DataMaskFlag)
		hint_mask << "DataMaskFlag";
	if (attribInfo.getHintMask() & AttribInfo::NameFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "NameFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::NameTypeFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "NameTypeFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::ServiceNameFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "ServiceNameFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::IDFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "IDFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::AttribFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "AttribFlag";
	}
	if (attribInfo.getHintMask() & AttribInfo::ServiceIDFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "ServiceIDFlag";
	}
/** type A **/
	switch (attribInfo.getNameType()) {
	case rdm::INSTRUMENT_NAME_UNSPECIFIED:	name_type = "INSTRUMENT_NAME_UNSPECIFIED"; break;
	case rdm::INSTRUMENT_NAME_RIC:		name_type = "INSTRUMENT_NAME_RIC"; break;
	case rdm::INSTRUMENT_NAME_MAX_RESERVED:	name_type = "INSTRUMENT_NAME_MAX_RESERVED"; break;
	}
	o << "\"AttribInfo\": { "
		  "\"HintMask\": \"" << hint_mask.str() << "\""
		", \"ID\": " << attribInfo.getID() <<
		", \"Name\": \"" << attribInfo.getName() << "\""
		", \"NameType\": \"" << name_type << "\""
		", \"ServiceID\": " << attribInfo.getServiceID() <<
		", \"ServiceName\": \"" << attribInfo.getServiceName() << "\""
		" }";
	return o;
}
} // namespace internal

inline
std::ostream& operator<< (std::ostream& o, const rfa::message::Manifest& manifest) {
	std::ostringstream hint_mask;
	using namespace message;
	if (manifest.getHintMask() & Manifest::SeqFlag)
		hint_mask << "SeqFlag";
	if (manifest.getHintMask() & Manifest::FilteredFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "FilteredFlag";
	}
	if (manifest.getHintMask() & Manifest::ItemGroupFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "ItemGroupFlag";
	}
	if (manifest.getHintMask() & Manifest::PermissionDataFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "PermissionDataFlag";
	}
	o << "\"Manifest\": { "
		  "\"FilteredCount\": " << manifest.getFilteredCount() <<
		", \"FilteredTime\": " << manifest.getFilteredTime() <<
		", \"HintMask\": \"" << hint_mask.str() << "\""
		", \"SeqNum\": " << manifest.getSeqNum() <<
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const PublisherPrincipalIdentity& identity) {
	o << "\"PrincipalIdentity\": { "
		  "\"Type\": \"PublisherPrincipalIdentity\""
		", \"UserAddress\": \"" << identity.getUserAddress() << "\""
		", \"UserID\": \"" << identity.getUserID() << "\""
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const StandardPrincipalIdentity& identity) {
	o << "\"PrincipalIdentity\": { "
		  "\"Type\": \"StandardPrincipalIdentity\""
		", \"AppName\": \"" << identity.getAppName() << "\""
		", \"Name\": \"" << identity.getName() << "\""
		", \"Password\": \"" << identity.getPassword() << "\""
		", \"Position\": \"" << identity.getPosition() << "\""
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const TokenizedPrincipalIdentity& identity) {
	o << "\"PrincipalIdentity\": { "
		   "\"Type\": \"TokenizedPrincipalIdentity\""
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const PrincipalIdentity& identity) {
	switch (identity.getIdentityType()) {
	case StandardPrincipalIdentityEnum:
		o << static_cast<const StandardPrincipalIdentity&>(identity);
		return o;
	case TokenizedPrincipalIdentityEnum:
		o << static_cast<const TokenizedPrincipalIdentity&>(identity);
		return o;
	case PublisherPrincipalIdentityEnum:
		o << static_cast<const PublisherPrincipalIdentity&>(identity);
		return o;
	default: break;
	}
	o << "\"PrincipalIdentity\": { "
		   "\"Type\": \"(Unknown)\""
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const QualityOfService& qos) {
	std::ostringstream rate, timeliness;
	if (qos.getRate() > 0) {
		rate << qos.getRate();
	} else {
/* Rfa design failure, constants are not constant. */
		const char *rate_string = "(Unknown)";
		if (qos.getRate() == QualityOfService::tickByTick)
			rate_string = "tickByTick";
		else if (qos.getRate() == QualityOfService::justInTimeFilteredRate)
			rate_string = "justInTimeFilteredRate";
		else if (qos.getRate() == QualityOfService::unspecifiedRate)
			rate_string = "unspecifiedRate";
		rate << '"' << rate_string << '"';
	}
	if (qos.getTimeliness() > 0) {
		timeliness << qos.getTimeliness();
	} else {
		const char *timeliness_string = "(Unknown)";
		if (qos.getTimeliness() == QualityOfService::realTime)
			timeliness_string = "realTime";
		else if (qos.getTimeliness() == QualityOfService::unspecifiedDelayedTimeliness)
			timeliness_string = "unspecifiedDelayedTimeliness";
		else if (qos.getTimeliness() == QualityOfService::unspecifiedTimeliness)
			timeliness_string = "unspecifiedTimeliness";
		timeliness << '"' << timeliness_string << '"';
	}
	o << "\"QualityOfService\": { "
		  "\"Rate\": " << rate.str() <<
		", \"Timeliness\": " << timeliness.str() <<
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const QualityOfServiceRequest& qos) {
	std::ostringstream best_rate, best_timeliness,
		worst_rate, worst_timeliness;
	const char* stream_property = "(Unknown)";
	if (qos.getBestRate() == QualityOfServiceRequest::tickByTick)
		best_rate << "\"tickByTick\"";
	else if (qos.getBestRate() == QualityOfServiceRequest::fastestFilteredRate)
		best_rate << "\"fastestFilteredRate\"";
	else if (qos.getBestRate() == QualityOfServiceRequest::justInTimeFilteredRate)
		best_rate << "\"justInTimeFilteredRate\"";
	else if (qos.getBestRate() == QualityOfServiceRequest::slowestRate)
		best_rate << "\"slowestRate\"";
	else
		best_rate << qos.getBestRate();
	if (qos.getBestTimeliness() == QualityOfServiceRequest::realTime)
		best_timeliness << "\"realTime\"";
	else if (qos.getBestTimeliness() == QualityOfServiceRequest::delayed)
		best_timeliness << "\"delayed\"";
	else
		best_timeliness << qos.getBestRate();
	switch (qos.getStreamProperty()) {
	case QualityOfServiceRequest::StaticStream:	stream_property = "StaticStream"; break;
	case QualityOfServiceRequest::DynamicStream:	stream_property = "DynamicStream"; break;
	default: break;
	}
	if (qos.getWorstRate() == QualityOfServiceRequest::tickByTick)
		worst_rate << "\"tickByTick\"";
	else if (qos.getWorstRate() == QualityOfServiceRequest::fastestFilteredRate)
		worst_rate << "\"fastestFilteredRate\"";
	else if (qos.getWorstRate() == QualityOfServiceRequest::justInTimeFilteredRate)
		worst_rate << "\"justInTimeFilteredRate\"";
	else if (qos.getWorstRate() == QualityOfServiceRequest::slowestRate)
		worst_rate << "\"slowestRate\"";
	else
		worst_rate << qos.getBestRate();
	if (qos.getWorstTimeliness() == QualityOfServiceRequest::realTime)
		worst_timeliness << "\"realTime\"";
	else if (qos.getWorstTimeliness() == QualityOfServiceRequest::delayed)
		worst_timeliness << "\"delayed\"";
	else
		worst_timeliness << qos.getBestRate();
	o << "\"QualityOfServiceRequest\": { "
		  "\"BestRate\": " << best_rate.str() <<
		", \"BestTimeliness\": " << best_timeliness.str() <<
		", \"StreamProperty\": \"" << stream_property << "\""
		", \"WorstRate\": " << worst_rate.str() <<
		", \"WorstTimeliness\": " << worst_timeliness.str() <<
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const RespStatus& status) {
	const char *data_state = "(Unknown)",
		*status_code = "(Unknown)",
		*stream_state = "(Unknown)";
	switch (status.getDataState()) {
	case RespStatus::UnspecifiedEnum:		data_state = "UnspecifiedEnum"; break;
	case RespStatus::OkEnum:			data_state = "OkEnum"; break;
	case RespStatus::SuspectEnum:			data_state = "SuspectEnum"; break;
	default: break;
	}
	switch (status.getStatusCode()) {
	case RespStatus::NoneEnum:			status_code = "NoneEnum"; break;
	case RespStatus::NotFoundEnum:			status_code = "NotFoundEnum"; break;
	case RespStatus::TimeoutEnum:			status_code = "TimeoutEnum"; break;
	case RespStatus::NotAuthorizedEnum:		status_code = "NotAuthorizedEnum"; break;
	case RespStatus::InvalidArgumentEnum:		status_code = "InvalidArgumentEnum"; break;
	case RespStatus::UsageErrorEnum:		status_code = "UsageErrorEnum"; break;
	case RespStatus::PreemptedEnum:			status_code = "PreemptedEnum"; break;
	case RespStatus::JustInTimeFilteringStartedEnum: status_code = "JustInTimeFilteringStartedEnum"; break;
	case RespStatus::TickByTickResumedEnum:		status_code = "TickByTickResumedEnum"; break;
	case RespStatus::FailoverStartedEnum:		status_code = "FailoverStartedEnum"; break;
	case RespStatus::FailoverCompletedEnum:		status_code = "FailoverCompletedEnum"; break;
	case RespStatus::GapDetectedEnum:		status_code = "GapDetectedEnum"; break;
	case RespStatus::NoResourcesEnum:		status_code = "NoResourcesEnum"; break;
	case RespStatus::TooManyItemsEnum:		status_code = "TooManyItemsEnum"; break;
	case RespStatus::AlreadyOpenEnum:		status_code = "AlreadyOpenEnum"; break;
	case RespStatus::SourceUnknownEnum:		status_code = "SourceUnknownEnum"; break;
	case RespStatus::NotOpenEnum:			status_code = "NotOpenEnum"; break;
	case RespStatus::NonUpdatingItemEnum:		status_code = "NonUpdatingItemEnum"; break;
	case RespStatus::UnsupportedViewTypeEnum:	status_code = "UnsupportedViewTypeEnum"; break;
	case RespStatus::InvalidViewEnum:		status_code = "InvalidViewEnum"; break;
	case RespStatus::FullViewProvidedEnum:		status_code = "FullViewProvidedEnum"; break;
	case RespStatus::UnableToRequestAsBatchEnum:	status_code = "UnableToRequestAsBatchEnum"; break;
	default: break;
	}
	switch (status.getStreamState()) {
	case RespStatus::UnspecifiedStreamStateEnum:	stream_state = "UnspecifiedStreamStateEnum"; break;
	case RespStatus::OpenEnum:			stream_state = "OpenEnum"; break;
	case RespStatus::NonStreamingEnum:		stream_state = "NonStreamingEnum"; break;
	case RespStatus::ClosedRecoverEnum:		stream_state = "ClosedRecoverEnum"; break;
	case RespStatus::ClosedEnum:			stream_state = "ClosedEnum"; break;
	case RespStatus::RedirectedEnum:		stream_state = "RedirectedEnum"; break;
	default: break;
	}
	o << "\"RespStatus\": { "
		  "\"DataState\": \"" << data_state << "\""
		", \"StatusCode\": \"" << status_code << "\""
		", \"StreamState\": \"" << stream_state << "\""
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const rfa::message::RespMsg& msg_) {
	std::ostringstream hint_mask, indication_mask, attrib_info;
	const char *model_type = "(Unknown)",
		*resp_type = "(Unknown)";
	using namespace message;
	if (msg_.getHintMask() & RespMsg::RespTypeNumFlag)
		hint_mask << "RespTypeNumFlag";
	if (msg_.getHintMask() & RespMsg::RespStatusFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "RespStatusFlag";
	}
	if (msg_.getHintMask() & RespMsg::QualityOfServiceFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "QualityOfServiceFlag";
	}
	if (msg_.getHintMask() & RespMsg::AttribInfoFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "AttribInfoFlag";
	}
	if (msg_.getHintMask() & RespMsg::ManifestFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "ManifestFlag";
	}
	if (msg_.getHintMask() & RespMsg::HeaderFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "HeaderFlag";
	}
	if (msg_.getHintMask() & RespMsg::PayloadFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "PayloadFlag";
	}
	if (msg_.getHintMask() & RespMsg::PrincipalIdentityFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "PrincipalIdentityFlag";
	}
	if (msg_.getIndicationMask() & RespMsg::DoNotCacheFlag)
		indication_mask << "DoNotCacheFlag";
	if (msg_.getIndicationMask() & RespMsg::DoNotFilterFlag) {
		if (!indication_mask.str().empty()) indication_mask << '|';
		indication_mask << "DoNotFilterFlag";
	}
	if (msg_.getIndicationMask() & RespMsg::ClearCacheFlag) {
		if (!indication_mask.str().empty()) indication_mask << '|';
		indication_mask << "ClearCacheFlag";
	}
	if (msg_.getIndicationMask() & RespMsg::RefreshCompleteFlag) {
		if (!indication_mask.str().empty()) indication_mask << '|';
		indication_mask << "RefreshCompleteFlag";
	}
	if (msg_.getIndicationMask() & RespMsg::DoNotRippleFlag) {
		if (!indication_mask.str().empty()) indication_mask << '|';
		indication_mask << "DoNotRippleFlag";
	}
	switch (msg_.getMsgModelType()) {
	case rdm::MMT_LOGIN:		model_type = "MMT_LOGIN"; break;
	case rdm::MMT_DIRECTORY:	model_type = "MMT_DIRECTORY"; break;
	case rdm::MMT_DICTIONARY:	model_type = "MMT_DICTIONARY"; break;
	case rdm::MMT_MARKET_PRICE:	model_type = "MMT_MARKET_PRICE"; break;
	case rdm::MMT_MARKET_BY_ORDER:	model_type = "MMT_MARKET_BY_ORDER"; break;
	case rdm::MMT_MARKET_BY_PRICE:	model_type = "MMT_MARKET_BY_PRICE"; break;
	case rdm::MMT_MARKET_MAKER:	model_type = "MMT_MARKET_MAKER"; break;
	case rdm::MMT_SYMBOL_LIST:	model_type = "MMT_SYMBOL_LIST"; break;
	case rdm::MMT_HISTORY:		model_type = "MMT_HISTORY"; break;
	default: break;
	}
	switch (msg_.getMsgModelType()) {
	case rdm::MMT_LOGIN: {
		const internal::LoginAttribInfo loginAttribInfo (msg_.getAttribInfo());
		attrib_info << loginAttribInfo;
		break;
	}
	case rdm::MMT_MARKET_BY_ORDER:
	case rdm::MMT_MARKET_BY_PRICE:
	case rdm::MMT_MARKET_MAKER:
	case rdm::MMT_MARKET_PRICE:
	case rdm::MMT_SYMBOL_LIST: {
		const internal::InstrumentAttribInfo instrumentAttribInfo (msg_.getAttribInfo());
		attrib_info << instrumentAttribInfo;
		break;
	}
	default:
		attrib_info << msg_.getAttribInfo();
		break;
	}
	switch (msg_.getRespType()) {
	case RespMsg::RefreshEnum:		resp_type = "RefreshEnum"; break;
	case RespMsg::StatusEnum:		resp_type = "StatusEnum"; break;
	case RespMsg::UpdateEnum:		resp_type = "UpdateEnum"; break;
	default: break;
	}
	o << "\"Msg\": { "
		  "\"HintMask\": \"" << hint_mask.str() << "\""
		", \"IndicationMask\": \"" << indication_mask.str() << "\""
		", \"MsgModelType\": \"" << model_type << "\""
		", \"MsgType\": \"RespMsg\""
		", " << attrib_info.str() <<
		", " << msg_.getManifest() <<
		", " << msg_.getPrincipalIdentity() <<
		", " << msg_.getQualityOfService() <<
		", " << msg_.getRespStatus() <<
		", \"RespType\": \"" << resp_type << "\""
		", \"RespTypeNum\": " << (int)msg_.getRespTypeNum() <<
		", \"isBlank\": " << (msg_.isBlank() ? "true" : "false") <<
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const rfa::message::ReqMsg& msg_) {
	std::ostringstream hint_mask, indication_mask, attrib_info, interaction_type;
	const char *model_type = "(Unknown)";
	using namespace message;
	if (msg_.getHintMask() & ReqMsg::PriorityFlag)
		hint_mask << "PriorityFlag";
	if (msg_.getHintMask() & ReqMsg::QualityOfServiceReqFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "QualityOfServiceReqFlag";
	}
	if (msg_.getHintMask() & ReqMsg::AttribInfoFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "AttribInfoFlag";
	}
	if (msg_.getHintMask() & ReqMsg::HeaderFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "HeaderFlag";
	}
	if (msg_.getHintMask() & ReqMsg::PayloadFlag) {
		if (!hint_mask.str().empty()) hint_mask << '|';
		hint_mask << "PayloadFlag";
	}
	if (msg_.getIndicationMask() & ReqMsg::AttribInfoInUpdatesFlag)
		indication_mask << "AttribInfoInUpdatesFlag";
	if (msg_.getIndicationMask() & ReqMsg::FilteredInUpdatesFlag) {
		if (!indication_mask.str().empty()) indication_mask << '|';
		indication_mask << "FilteredInUpdatesFlag";
	}
	if (msg_.getIndicationMask() & ReqMsg::ViewFlag) {
		if (!indication_mask.str().empty()) indication_mask << '|';
		indication_mask << "ViewFlag";
	}
	if (msg_.getIndicationMask() & ReqMsg::BatchFlag) {
		if (!indication_mask.str().empty()) indication_mask << '|';
		indication_mask << "BatchFlag";
	}
	switch (msg_.getMsgModelType()) {
	case rdm::MMT_LOGIN:		model_type = "MMT_LOGIN"; break;
	case rdm::MMT_DIRECTORY:	model_type = "MMT_DIRECTORY"; break;
	case rdm::MMT_DICTIONARY:	model_type = "MMT_DICTIONARY"; break;
	case rdm::MMT_MARKET_PRICE:	model_type = "MMT_MARKET_PRICE"; break;
	case rdm::MMT_MARKET_BY_ORDER:	model_type = "MMT_MARKET_BY_ORDER"; break;
	case rdm::MMT_MARKET_BY_PRICE:	model_type = "MMT_MARKET_BY_PRICE"; break;
	case rdm::MMT_MARKET_MAKER:	model_type = "MMT_MARKET_MAKER"; break;
	case rdm::MMT_SYMBOL_LIST:	model_type = "MMT_SYMBOL_LIST"; break;
	case rdm::MMT_HISTORY:		model_type = "MMT_HISTORY"; break;
	default: break;
	}
	switch (msg_.getMsgModelType()) {
	case rdm::MMT_LOGIN: {
		const internal::LoginAttribInfo loginAttribInfo (msg_.getAttribInfo());
		attrib_info << loginAttribInfo;
		break;
	}
	case rdm::MMT_MARKET_BY_ORDER:
	case rdm::MMT_MARKET_BY_PRICE:
	case rdm::MMT_MARKET_MAKER:
	case rdm::MMT_MARKET_PRICE:
	case rdm::MMT_SYMBOL_LIST: {
		const internal::InstrumentAttribInfo instrumentAttribInfo (msg_.getAttribInfo());
		attrib_info << instrumentAttribInfo;
		break;
	}
	default:
		attrib_info << msg_.getAttribInfo();
		break;
	}
	if (msg_.getInteractionType() & ReqMsg::InitialImageFlag)
		interaction_type << "InitialImageFlag";
	if (msg_.getInteractionType() & ReqMsg::InterestAfterRefreshFlag) {
		if (!interaction_type.str().empty()) interaction_type << '|';
		interaction_type << "InterestAfterRefreshFlag";
	}
	if (msg_.getInteractionType() & ReqMsg::PauseFlag) {
		if (!interaction_type.str().empty()) interaction_type << '|';
		interaction_type << "PauseFlag";
	}
	o << "\"Msg\": { "
		  "\"HintMask\": \"" << hint_mask.str() << "\""
		", \"IndicationMask\": \"" << indication_mask.str() << "\""
		", \"MsgModelType\": \"" << model_type << "\""
		", \"MsgType\": \"ReqMsg\""
		", " << attrib_info.str() <<
//		", " << msg_.getEncodedBuffer() <<
//		", " << msg_.getHeader() <<
		", \"InteractionType\": \"" << interaction_type.str() << "\""
//		", " << msg_.getPayload() <<
		", \"PriorityClass\": " << (int)msg_.getPriorityClass() <<
		", \"PriorityCount\": " << (int)msg_.getPriorityCount() <<
		", " << msg_.getRequestedQualityOfService() <<
		", \"isBlank\": " << (msg_.isBlank() ? "true" : "false") <<
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const Msg& msg_) {
	const char *hint_mask = "(Unknown)",
		*indication_mask = "(Unknown)",
		*model_type = "(Unknown)",
		*msg_type = "(Unknown)";
	switch (msg_.getMsgType()) {
	case message::RespMsgEnum:
		o << static_cast<const rfa::message::RespMsg&>(msg_);
		return o;
	case message::ReqMsgEnum:
		o << static_cast<const rfa::message::ReqMsg&>(msg_);
		return o;
	case message::GenericMsgEnum:	msg_type = "GenericMsg"; break;
	case message::PostMsgEnum:	msg_type = "PostMsg"; break;
	case message::AckMsgEnum:	msg_type = "AckMsg"; break;
	default: break;
	}
	o << "\"Msg\": { "
		  "\"HintMask\": \"" << hint_mask << "\""
		", \"IndicationMask\": \"" << indication_mask << "\""
		", \"MsgModelType\": \"" << model_type << "\""
		", \"MsgType\": \"" << msg_type << "\""
		", \"isBlank\": " << (msg_.isBlank() ? "true" : "false") <<
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const rfa::sessionLayer::ConnectionStatus & status_) {
	const char *state = "(Unknown)",
		*status_code = "(Uknown)";
	using namespace sessionLayer;
	switch (status_.getState()) {
	case ConnectionStatus::Up:	state = "Up"; break;
	case ConnectionStatus::Down:	state = "Down"; break;
	default: break;
	}
	switch (status_.getStatusCode()) {
	case ConnectionStatus::None:			status_code = "None"; break;
/* lol, also variant form ConnectionStatus::AcessDenied */
	case ConnectionStatus::AccessDenied:		status_code = "AccessDenied"; break;
	case ConnectionStatus::IntermittentProblems:	status_code = "IntermittentProblems"; break;
	case ConnectionStatus::ServerSwitched:		status_code = "ServerSwitched"; break;
	case ConnectionStatus::Closed:			status_code = "Closed"; break;
	default: break;
	}
	o << "\"Status\": { "
		  "\"State\": \"" << state << "\""
		", \"StatusCode\": " << status_code << "\""
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const rfa::sessionLayer::ConnectionEvent & event_) {
	const char *connection_type = "(Unknown)";
	using namespace sessionLayer;
	switch (event_.getConnectionType()) {
	case ConnectionEvent::SASS3:			connection_type = "SASS3"; break;
	case ConnectionEvent::SSLED:			connection_type = "SSLED"; break;
	case ConnectionEvent::RV:			connection_type = "RV"; break;
	case ConnectionEvent::SSLED_MP:			connection_type = "SSLED_MP"; break;
	case ConnectionEvent::RSSL:			connection_type = "RSSL"; break;
	case ConnectionEvent::RSSL_PROV:		connection_type = "RSSL_PROV"; break;
	case ConnectionEvent::RSSL_CPROV:		connection_type = "RSSL_CPROV"; break;
	case ConnectionEvent::RSSL_NIPROV:		connection_type = "RSSL_NIPROV"; break;
	case ConnectionEvent::RSSL_NIPROV_MCAST:	connection_type = "RSSL_NIPROV_MCAST"; break;
	default: break;
	}
	o << "\"Event\": { "
		  "\"Type\": \"ConnectionEvent\""
		", \"ConnectionName\": \"" << event_.getConnectionName() << "\""
		", \"ConnectionType\": \"" << connection_type << "\""
		", " << event_.getStatus() <<
		", \"isEventStreamClosed\": " << (event_.isEventStreamClosed() ? "true" : "false") <<
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const rfa::sessionLayer::OMMItemEvent & event_) {
	o << "\"Event\": { "
		  "\"Type\": \"OMMItemEvent\""
		", " << event_.getMsg() <<
		", \"isEventStreamClosed\": " << (event_.isEventStreamClosed() ? "true" : "false") <<
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const rfa::sessionLayer::OMMActiveClientSessionEvent & event_) {
	o << "\"Event\": { "
		  "\"Type\": \"OMMActiveClientSessionEvent\""
		", \"ClientHostName\": \"" << event_.getClientHostName() << "\""
		", \"ClientIPAddress\": \"" << event_.getClientIPAddress() << "\""
		", \"ListenerName\": \"" << event_.getListenerName() << "\""
		", \"isEventStreamClosed\": " << (event_.isEventStreamClosed() ? "true" : "false") <<
		" }";
	return o;
}

inline
std::ostream& operator<< (std::ostream& o, const rfa::sessionLayer::OMMSolicitedItemEvent & event_) {
	o << "\"Event\": { "
		  "\"Type\": \"OMMSolicitedItemEvent\""
		", " << event_.getMsg() <<
		", \"isEventStreamClosed\": " << (event_.isEventStreamClosed() ? "true" : "false") <<
		" }";
	return o;
}
inline
std::ostream& operator<< (std::ostream& o, const Event& event_) {
	const char* type_name;
	switch (event_.getType()) {
	case common::EventQueueStatusEventEnum:					type_name = "EventQueueStatusEventEnum"; break;
	case common::ComplEventEnum:						type_name = "ComplEventEnum"; break;

	case sessionLayer::MarketDataItemEventEnum:				type_name = "MarketDataItemEventEnum"; break;
	case sessionLayer::MarketDataDictEventEnum:				type_name = "MarketDataDictEventEnum"; break; 
	case sessionLayer::MarketDataSvcEventEnum:				type_name = "MarketDataSvcEventEnum"; break;
	case sessionLayer::MarketDataManagedPubChannelReqEventEnum:		type_name = "MarketDataManagedPubChannelReqEventEnum"; break;
	case sessionLayer::MarketDataManagedPubItemReqEventEnum:		type_name = "MarketDataManagedPubItemReqEventEnum"; break;
	case sessionLayer::PubErrorEventEnum:					type_name = "PubErrorEventEnum"; break;  
	case sessionLayer::MarketDataItemContReplyEventEnum:			type_name = "MarketDataItemContReplyEventEnum"; break;
	case sessionLayer::SessionEventEnum:					type_name = "SessionEventEnum"; break;
	case sessionLayer::MarketDataCBR_NameEventEnum:				type_name = "MarketDataCBR_NameEventEnum"; break;
	case sessionLayer::EntitlementsAuthenticationEventEnum:			type_name = "EntitlementsAuthenticationEventEnum"; break;
	case sessionLayer::ConnectionEventEnum:
		o << static_cast<const rfa::sessionLayer::ConnectionEvent&>(event_);
		return o;
	case sessionLayer::MarketDataManagedActiveItemsPubEventEnum:		type_name = "MarketDataManagedActiveItemsPubEventEnum"; break;
	case sessionLayer::MarketDataManagedInactiveItemsPubEventEnum:		type_name = "MarketDataManagedInactiveItemsPubEventEnum"; break;
	case sessionLayer::MarketDataManagedPubMirroringModeEventEnum:		type_name = "MarketDataManagedPubMirroringModeEventEnum"; break; 
	case sessionLayer::MarketDataManagedItemContReqPubEventEnum:		type_name = "MarketDataManagedItemContReqPubEventEnum"; break;
	case sessionLayer::MarketDataManagedActiveClientSessionPubEventEnum:	type_name = "MarketDataManagedActiveClientSessionPubEventEnum"; break;
	case sessionLayer::MarketDataManagedInactiveClientSessionPubEventEnum:	type_name = "MarketDataManagedInactiveClientSessionPubEventEnum"; break;
	case sessionLayer::OMMItemEventEnum:
		o << static_cast<const rfa::sessionLayer::OMMItemEvent&>(event_);
		return o;
	case sessionLayer::OMMActiveClientSessionEventEnum:
		o << static_cast<const rfa::sessionLayer::OMMActiveClientSessionEvent&>(event_);
		return o;
	case sessionLayer::OMMInactiveClientSessionEventEnum:			type_name = "OMMInactiveClientSessionEventEnum"; break;
	case sessionLayer::OMMSolicitedItemEventEnum:
		o << static_cast<const rfa::sessionLayer::OMMSolicitedItemEvent&>(event_);
		return o;
	case sessionLayer::OMMCmdErrorEventEnum:				type_name = "OMMCmdErrorEventEnum"; break;

	case logger::LoggerNotifyEventEnum:					type_name = "LoggerNotifyEventEnum"; break;
	default:
		type_name = "(Unknown)";
		break;
	}
	o << "\"Event\": { "
		  "\"Type\": \"" << type_name << "\""
		", \"isEventStreamClosed\": " << (event_.isEventStreamClosed() ? "true" : "false") <<
		" }";
	return o;
}

} /* namespace common */
} /* namespace rfa */

#endif /* __RFA_OSTREAM_HH__ */

/* eof */
