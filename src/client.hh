/* RFA provider client session.
 */

#ifndef __CLIENT_HH__
#define __CLIENT_HH__
#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>

/* Boost Posix Time */
#include <boost/date_time/posix_time/posix_time.hpp>

/* Boost noncopyable base class */
#include <boost/utility.hpp>

/* RFA 7.2 */
#include <rfa/rfa.hh>

#include "rfa.hh"
#include "config.hh"
#include "deleter.hh"

namespace anaguma
{
/* Performance Counters */
	enum {
		CLIENT_PC_RFA_MSGS_SENT,
		CLIENT_PC_RFA_EVENTS_RECEIVED,
		CLIENT_PC_RFA_EVENTS_DISCARDED,
		CLIENT_PC_OMM_SOLICITED_ITEM_EVENTS_RECEIVED,
		CLIENT_PC_OMM_SOLICITED_ITEM_EVENTS_DISCARDED,
		CLIENT_PC_REQUEST_MSGS_RECEIVED,
		CLIENT_PC_REQUEST_MSGS_DISCARDED,
		CLIENT_PC_MMT_LOGIN_RECEIVED,
		CLIENT_PC_MMT_LOGIN_VALIDATED,
		CLIENT_PC_MMT_LOGIN_MALFORMED,
		CLIENT_PC_MMT_LOGIN_REJECTED,
		CLIENT_PC_MMT_LOGIN_ACCEPTED,
		CLIENT_PC_MMT_LOGIN_RESPONSE_VALIDATED,
		CLIENT_PC_MMT_LOGIN_RESPONSE_MALFORMED,
		CLIENT_PC_MMT_LOGIN_EXCEPTION,
		CLIENT_PC_MMT_DIRECTORY_REQUEST_RECEIVED,
		CLIENT_PC_MMT_DIRECTORY_REQUEST_VALIDATED,
		CLIENT_PC_MMT_DIRECTORY_REQUEST_MALFORMED,
		CLIENT_PC_MMT_DIRECTORY_VALIDATED,
		CLIENT_PC_MMT_DIRECTORY_MALFORMED,
		CLIENT_PC_MMT_DIRECTORY_SENT,
		CLIENT_PC_MMT_DIRECTORY_EXCEPTION,
		CLIENT_PC_MMT_DICTIONARY_REQUEST_RECEIVED,
		CLIENT_PC_MMT_DICTIONARY_REQUEST_VALIDATED,
		CLIENT_PC_MMT_DICTIONARY_REQUEST_MALFORMED,
		CLIENT_PC_ITEM_REQUEST_RECEIVED,
		CLIENT_PC_ITEM_REISSUE_REQUEST_RECEIVED,
		CLIENT_PC_ITEM_CLOSE_REQUEST_RECEIVED,
		CLIENT_PC_ITEM_REQUEST_MALFORMED,
		CLIENT_PC_ITEM_REQUEST_BEFORE_LOGIN,
		CLIENT_PC_ITEM_DUPLICATE_SNAPSHOT,
		CLIENT_PC_ITEM_REQUEST_DISCARDED,
		CLIENT_PC_ITEM_REQUEST_REJECTED,
		CLIENT_PC_ITEM_VALIDATED,
		CLIENT_PC_ITEM_MALFORMED,
		CLIENT_PC_ITEM_NOT_FOUND,
		CLIENT_PC_ITEM_SENT,
		CLIENT_PC_ITEM_CLOSED,
		CLIENT_PC_ITEM_EXCEPTION,
		CLIENT_PC_OMM_INACTIVE_CLIENT_SESSION_RECEIVED,
		CLIENT_PC_OMM_INACTIVE_CLIENT_SESSION_EXCEPTION,
		CLIENT_PC_MAX
	};

	class provider_t;
	class item_stream_t;

	class client_t :
		public std::enable_shared_from_this<client_t>,
		public rfa::common::Client,
		boost::noncopyable
	{
	public:
		client_t (std::shared_ptr<provider_t> provider, const rfa::common::Handle* handle, const char* address);
		~client_t();

		bool GetAssociatedMetaInfo();

/* RFA event callback. */
		void processEvent (const rfa::common::Event& event) override;

		bool Init (rfa::common::Handle*const handle);
		rfa::common::Handle*const GetHandle() const {
			return handle_;
		}
		uint8_t GetRwfMajorVersion() const {
			return rwf_major_version_;
		}
		uint8_t GetRwfMinorVersion() const {
			return rwf_minor_version_;
		}

	private:
		void OnOMMSolicitedItemEvent (const rfa::sessionLayer::OMMSolicitedItemEvent& event);
		void OnReqMsg (const rfa::message::ReqMsg& msg, rfa::sessionLayer::RequestToken*const token);
		void OnLoginRequest (const rfa::message::ReqMsg& msg, rfa::sessionLayer::RequestToken*const token);
		void OnDirectoryRequest (const rfa::message::ReqMsg& msg, rfa::sessionLayer::RequestToken*const token);
		void OnDictionaryRequest (const rfa::message::ReqMsg& msg, rfa::sessionLayer::RequestToken*const token);
		void OnItemRequest (const rfa::message::ReqMsg& msg, rfa::sessionLayer::RequestToken*const token);
		void OnItemSnapshotRequest (const rfa::message::ReqMsg& msg, rfa::sessionLayer::RequestToken*const token);
		void OnItemStreamingRequest (const rfa::message::ReqMsg& msg, rfa::sessionLayer::RequestToken*const token);
		void OnOMMItemEvent (const rfa::sessionLayer::OMMItemEvent& event);
                void OnRespMsg (const rfa::message::RespMsg& msg);
                void OnLoginResponse (const rfa::message::RespMsg& msg);
                void OnLoginSuccess (const rfa::message::RespMsg& msg);
                void OnLoginSuspect (const rfa::message::RespMsg& msg);
                void OnLoginClosed (const rfa::message::RespMsg& msg);
		void OnOMMInactiveClientSessionEvent (const rfa::sessionLayer::OMMInactiveClientSessionEvent& event);

		bool RejectLogin (const rfa::message::ReqMsg& msg, rfa::sessionLayer::RequestToken*const login_token);
		bool AcceptLogin (const rfa::message::ReqMsg& msg, rfa::sessionLayer::RequestToken*const login_token);
		bool SendDirectoryResponse (rfa::sessionLayer::RequestToken*const token, const char* service_name, uint32_t filter_mask);
		bool SendClose (rfa::sessionLayer::RequestToken*const token, uint32_t service_id, uint8_t model_type, const char* name, bool use_attribinfo_in_updates, uint8_t status_code);

		bool SendInitial (uint32_t service_id, const rfa::common::RFA_String& stream_name, const boost::posix_time::ptime& timestamp, uint8_t rwf_major_version, uint8_t rwf_minor_version, rfa::sessionLayer::RequestToken*const token);

		uint32_t Submit (rfa::message::RespMsg*const msg, rfa::sessionLayer::RequestToken*const token, void* closure) throw (rfa::common::InvalidUsageException);

		std::shared_ptr<provider_t> provider_;

/* unique id per connection. */
		std::string prefix_;

/* client details. */
		std::string address_;
		std::string name_;

/* RFA Client Session event consumer. */
		rfa::common::Handle* handle_;

/* RFA login token for closing out the Client Session. */
		rfa::sessionLayer::RequestToken* login_token_;

/* Watchlist of all items. */
		std::unordered_map<rfa::sessionLayer::RequestToken*const, std::weak_ptr<item_stream_t>> items_;

/* Reuters Wire Format versions. */
		uint8_t rwf_major_version_;
		uint8_t rwf_minor_version_;

/* Pre-allocated parsing state */
		std::string url_, value_;
		std::string underlying_symbol_;
		std::istringstream iss_;

/* Item requests may appear before login success has been granted.
 */
		bool is_logged_in_;

		friend provider_t;

/** Performance Counters **/
		boost::posix_time::ptime creation_time_, last_activity_;
		uint32_t cumulative_stats_[CLIENT_PC_MAX];
		uint32_t snap_stats_[CLIENT_PC_MAX];

#ifdef STITCHMIB_H
		friend Netsnmp_Next_Data_Point anagumaClientTable_get_next_data_point;
		friend Netsnmp_Node_Handler anagumaClientTable_handler;

		friend Netsnmp_Next_Data_Point anagumaClientPerformanceTable_get_next_data_point;
		friend Netsnmp_Node_Handler anagumaClientPerformanceTable_handler;
#endif /* STITCHMIB_H */
	};

} /* namespace anaguma */

#endif /* __CLIENT_HH__ */

/* eof */
