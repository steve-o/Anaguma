/* UPA provider client session.
 */

#ifndef CLIENT_HH_
#define CLIENT_HH_

#include <cstdint>
#include <memory>
#include <unordered_map>

/* Boost Posix Time */
#include <boost/date_time/posix_time/posix_time.hpp>

/* Boost noncopyable base class */
#include <boost/utility.hpp>

/* UPA 7.4 */
#include <upa/upa.h>

#include "upa.hh"
#include "config.hh"
#include "deleter.hh"

namespace anaguma
{
/* Performance Counters */
	enum {
		CLIENT_PC_UPA_MSGS_SENT,
		CLIENT_PC_UPA_MSGS_RECEIVED,
		CLIENT_PC_UPA_MSGS_REJECTED,
		CLIENT_PC_REQUEST_MSGS_RECEIVED,
		CLIENT_PC_REQUEST_MSGS_REJECTED,
		CLIENT_PC_CLOSE_MSGS_RECEIVED,
		CLIENT_PC_CLOSE_MSGS_DISCARDED,
		CLIENT_PC_MMT_LOGIN_RECEIVED,
		CLIENT_PC_MMT_LOGIN_MALFORMED,
		CLIENT_PC_MMT_LOGIN_REJECTED,
		CLIENT_PC_MMT_LOGIN_ACCEPTED,
		CLIENT_PC_MMT_LOGIN_RESPONSE_VALIDATED,
		CLIENT_PC_MMT_LOGIN_RESPONSE_MALFORMED,
		CLIENT_PC_MMT_LOGIN_EXCEPTION,
		CLIENT_PC_MMT_LOGIN_CLOSE_RECEIVED,
		CLIENT_PC_MMT_DIRECTORY_REQUEST_RECEIVED,
		CLIENT_PC_MMT_DIRECTORY_VALIDATED,
		CLIENT_PC_MMT_DIRECTORY_MALFORMED,
		CLIENT_PC_MMT_DIRECTORY_SENT,
		CLIENT_PC_MMT_DIRECTORY_EXCEPTION,
		CLIENT_PC_MMT_DIRECTORY_CLOSE_RECEIVED,
		CLIENT_PC_MMT_DICTIONARY_REQUEST_RECEIVED,
		CLIENT_PC_MMT_DICTIONARY_CLOSE_RECEIVED,
		CLIENT_PC_ITEM_REQUEST_RECEIVED,
		CLIENT_PC_ITEM_REQUEST_MALFORMED,
		CLIENT_PC_ITEM_REQUEST_BEFORE_LOGIN,
		CLIENT_PC_ITEM_STREAMING_REQUEST_RECEIVED,
		CLIENT_PC_ITEM_REISSUE_REQUEST_RECEIVED,
		CLIENT_PC_ITEM_SNAPSHOT_REQUEST_RECEIVED,
		CLIENT_PC_ITEM_DUPLICATE_SNAPSHOT,
		CLIENT_PC_ITEM_REQUEST_REJECTED,
		CLIENT_PC_ITEM_VALIDATED,
		CLIENT_PC_ITEM_MALFORMED,
		CLIENT_PC_ITEM_NOT_FOUND,
		CLIENT_PC_ITEM_SENT,
		CLIENT_PC_ITEM_CLOSED,
		CLIENT_PC_ITEM_EXCEPTION,
		CLIENT_PC_ITEM_CLOSE_RECEIVED,
		CLIENT_PC_ITEM_CLOSE_MALFORMED,
		CLIENT_PC_ITEM_CLOSE_VALIDATED,
		CLIENT_PC_OMM_INACTIVE_CLIENT_SESSION_RECEIVED,
		CLIENT_PC_OMM_INACTIVE_CLIENT_SESSION_EXCEPTION,
		CLIENT_PC_MAX
	};

	class provider_t;
	class item_stream_t;

	class client_t :
		public std::enable_shared_from_this<client_t>,
		boost::noncopyable
	{
	public:
		client_t (std::shared_ptr<provider_t> provider, RsslChannel* handle, const char* address);
		~client_t();

		bool Init();
		bool Close();

		RsslChannel*const GetHandle() const {
			return handle_;
		}
		uint8_t GetRwfMajorVersion() const {
			return handle_->majorVersion;
		}
		uint8_t GetRwfMinorVersion() const {
			return handle_->minorVersion;
		}

	private:
		bool OnMsg (const RsslMsg* msg);

		bool OnRequestMsg (const RsslRequestMsg* msg);
		bool OnLoginRequest (const RsslRequestMsg* msg);
		bool OnDirectoryRequest (const RsslRequestMsg* msg);
		bool OnDictionaryRequest (const RsslRequestMsg* msg);
		bool OnItemRequest (const RsslRequestMsg* msg);
		bool OnItemSnapshotRequest (const RsslRequestMsg* msg, int32_t token);
		bool OnItemStreamingRequest (const RsslRequestMsg* msg, int32_t token);

		bool OnCloseMsg (const RsslCloseMsg* msg);
		bool OnItemClose (const RsslCloseMsg* msg);

		bool RejectLogin (const RsslRequestMsg* msg, int32_t login_token);
		bool AcceptLogin (const RsslRequestMsg* msg, int32_t login_token);

		bool SendDirectoryResponse (int32_t token, const char* service_name, uint32_t filter_mask);
bool SendDirectoryUpdate (const char* service_name);
		bool SendClose (int32_t token, uint16_t service_id, uint8_t model_type, const char* name, size_t name_len, bool use_attribinfo_in_updates, uint8_t status_code);
		bool SendInitial (uint16_t service_id, int32_t token, const char* name, size_t name_len, const boost::posix_time::ptime& timestamp);
		int Submit (RsslBuffer* buf);

		const boost::posix_time::ptime& NextPing() const {
			return next_ping_;
		}
		const boost::posix_time::ptime& NextPong() const {
			return next_pong_;
		}
		void SetNextPing (const boost::posix_time::ptime& time_) {
			next_ping_ = time_;
		}
		void SetNextPong (const boost::posix_time::ptime& time_) {
			next_pong_ = time_;
		}
		void IncrementPendingCount() {
			pending_count_++;
		}
		void ClearPendingCount() {
			pending_count_ = 0;
		}
		unsigned GetPendingCount() const {
			return pending_count_;
		}

		std::shared_ptr<provider_t> provider_;

/* unique id per connection. */
		std::string prefix_;

/* client details. */
		std::string address_;
		std::string name_;

/* UPA socket. */
		RsslChannel* handle_;
/* Pending messages to flush. */
		unsigned pending_count_;

/* Watchlist of all items. */
//		std::unordered_map<rfa::sessionLayer::RequestToken*const, std::weak_ptr<item_stream_t>> items_;

/* Pre-allocated parsing state */
		std::string url_, value_;
		std::string underlying_symbol_;
		std::istringstream iss_;

/* Item requests may appear before login success has been granted.
 */
		bool is_logged_in_;
		int32_t login_token_;
int32_t directory_token_;
/* RSSL keepalive state. */
		boost::posix_time::ptime next_ping_;
		boost::posix_time::ptime next_pong_;
		unsigned ping_interval_;

		friend provider_t;

/** Performance Counters **/
		boost::posix_time::ptime creation_time_, last_activity_;
		uint32_t cumulative_stats_[CLIENT_PC_MAX];
		uint32_t snap_stats_[CLIENT_PC_MAX];

#ifdef ANAGUMAMIB_H
		friend Netsnmp_Next_Data_Point anagumaClientTable_get_next_data_point;
		friend Netsnmp_Node_Handler anagumaClientTable_handler;

		friend Netsnmp_Next_Data_Point anagumaClientPerformanceTable_get_next_data_point;
		friend Netsnmp_Node_Handler anagumaClientPerformanceTable_handler;
#endif /* ANAGUMAMIB_H */
	};

} /* namespace anaguma */

#endif /* CLIENT_HH_ */

/* eof */