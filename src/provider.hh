/* UPA provider.
 */

#ifndef PROVIDER_HH_
#define PROVIDER_HH_

#include <winsock2.h>

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>

/* Boost Atomics */
#include <boost/atomic.hpp>

/* Boost Posix Time */
#include <boost/date_time/posix_time/posix_time.hpp>

/* Boost noncopyable base class */
#include <boost/utility.hpp>

/* Boost threading. */
#include <boost/thread.hpp>

/* UPA 7.2 */
#include <upa/upa.h>

#include "upa.hh"
#include "config.hh"
#include "deleter.hh"

namespace anaguma
{
/* Performance Counters */
	enum {
		PROVIDER_PC_BYTES_RECEIVED,
		PROVIDER_PC_UNCOMPRESSED_BYTES_RECEIVED,
		PROVIDER_PC_MSGS_SENT,
		PROVIDER_PC_UPA_MSGS_ENQUEUED,
		PROVIDER_PC_UPA_MSGS_SENT,
		PROVIDER_PC_UPA_MSGS_RECEIVED,
		PROVIDER_PC_UPA_MSGS_DECODED,
		PROVIDER_PC_UPA_MSGS_MALFORMED,
		PROVIDER_PC_UPA_MSGS_VALIDATED,
		PROVIDER_PC_CONNECTION_RECEIVED,
		PROVIDER_PC_CONNECTION_REJECTED,
		PROVIDER_PC_CONNECTION_ACCEPTED,
		PROVIDER_PC_CONNECTION_EXCEPTION,
		PROVIDER_PC_RWF_VERSION_UNSUPPORTED,
		PROVIDER_PC_UPA_PING_SENT,
		PROVIDER_PC_UPA_PONG_RECEIVED,
		PROVIDER_PC_UPA_PONG_TIMEOUT,
		PROVIDER_PC_UPA_PROTOCOL_DOWNGRADE,
		PROVIDER_PC_UPA_FLUSH,
		PROVIDER_PC_OMM_ACTIVE_CLIENT_SESSION_RECEIVED,
		PROVIDER_PC_OMM_ACTIVE_CLIENT_SESSION_EXCEPTION,
		PROVIDER_PC_CLIENT_SESSION_REJECTED,
		PROVIDER_PC_CLIENT_SESSION_ACCEPTED,
		PROVIDER_PC_UPA_RECONNECT,
		PROVIDER_PC_UPA_CONGESTION_DETECTED,
		PROVIDER_PC_UPA_SLOW_READER,
		PROVIDER_PC_UPA_PACKET_GAP_DETECTED,
		PROVIDER_PC_UPA_READ_FAILURE,
		PROVIDER_PC_CLIENT_INIT_EXCEPTION,
		PROVIDER_PC_DIRECTORY_MAP_EXCEPTION,
		PROVIDER_PC_UPA_PING_EXCEPTION,
		PROVIDER_PC_UPA_PING_FLUSH_FAILED,
		PROVIDER_PC_UPA_PING_NO_BUFFERS,
		PROVIDER_PC_UPA_WRITE_EXCEPTION,
		PROVIDER_PC_UPA_WRITE_FLUSH_FAILED,
		PROVIDER_PC_UPA_WRITE_NO_BUFFERS,
/* marker */
		PROVIDER_PC_MAX
	};

	class client_t;
	class item_stream_t;

	class request_t : boost::noncopyable
	{
	public:
		request_t (std::shared_ptr<item_stream_t> item_stream_, std::shared_ptr<client_t> client_, bool use_attribinfo_in_updates_)
			: item_stream (item_stream_),
			  client (client_),
			  use_attribinfo_in_updates (use_attribinfo_in_updates_),
			  has_initial_image (false)
		{
		}

		std::weak_ptr<item_stream_t> item_stream;
		std::weak_ptr<client_t> client;
		const bool use_attribinfo_in_updates;	/* can theoretically change in reissue */
/* RFA will return a CmdError message if the provider application submits data
 * before receiving a login success message.  Mute downstream publishing until
 * permission is granted to submit data.
 */
		boost::atomic_bool has_initial_image;
	};

	class item_stream_t : boost::noncopyable
	{
	public:
		item_stream_t ()
		{
		}

/* Fixed name for this stream. */
//		rfa::common::RFA_String rfa_name;
/* Request tokens for clients, can be more than one per client. */
//		std::unordered_map<rfa::sessionLayer::RequestToken*const, std::shared_ptr<request_t>> requests;
		boost::shared_mutex lock;
	};

	class provider_t :
		public std::enable_shared_from_this<provider_t>,
		boost::noncopyable
	{
	public:
		provider_t (const config_t& config, std::shared_ptr<upa_t> upa);
		~provider_t();

		bool Init();

		void Run();
		void Quit();
		void Close();

		uint16_t GetRwfVersion() const {
			return min_rwf_version_.load();
		}
		const char* GetServiceName() const {
			return config_.service_name.c_str();
		}
		uint16_t GetServiceId() const {
			return service_id_;
		}

	private:
		bool DoWork();

		void OnConnection (RsslServer* rssl_sock);
		void RejectConnection (RsslServer* rssl_sock);
		void AcceptConnection (RsslServer* rssl_sock);

		void OnCanReadWithoutBlocking (RsslChannel* handle);
		void OnCanWriteWithoutBlocking (RsslChannel* handle);
		void Abort (RsslChannel* handle);
		void Close (RsslChannel* handle);

		void OnInitializingState (RsslChannel* handle);
		void OnActiveClientSession (RsslChannel* handle);
		void RejectClientSession (RsslChannel* handle, const char* address);
		bool AcceptClientSession (RsslChannel* handle, const char* address);
//		bool EraseClientSession (rfa::common::Handle*const handle);

		void OnActiveState (RsslChannel* handle);
		void OnMsg (RsslChannel* handle, RsslBuffer* buf);

		bool GetDirectoryMap (RsslEncodeIterator*const it, const char* service_name, uint32_t filter_mask, unsigned map_action);
		bool GetServiceDirectory (RsslEncodeIterator*const it, const char* service_name, uint32_t filter_mask);
		bool GetServiceFilterList (RsslEncodeIterator*const it, uint32_t filter_mask);
		bool GetServiceInformation (RsslEncodeIterator*const it);
		bool GetServiceCapabilities (RsslEncodeIterator*const it);
		bool GetServiceDictionaries (RsslEncodeIterator*const it);
		bool GetServiceQoS (RsslEncodeIterator*const it);
		bool GetServiceState (RsslEncodeIterator*const it);

		bool AddRequest (int32_t token, std::shared_ptr<anaguma::client_t> client);
		bool RemoveRequest (int32_t token);

		int Submit (RsslChannel* c, RsslBuffer* buf);
		int Ping (RsslChannel* c);

		void SetServiceId (uint16_t service_id) {
			service_id_.store (service_id);
		}

		const config_t& config_;

/* UPA context. */
		std::shared_ptr<upa_t> upa_;
		RsslServer* rssl_sock_;
/* This flag is set to false when Run should return. */
		bool keep_running_;

		int in_nfds_, out_nfds_;
		fd_set in_rfds_, in_wfds_, in_efds_;
		fd_set out_rfds_, out_wfds_, out_efds_;
		struct timeval in_tv_, out_tv_;

/* UPA connection directory */
		std::list<RsslChannel*const> connections_;

/* UPA Client Session directory */
		std::unordered_map<RsslChannel*const, std::shared_ptr<client_t>> clients_;
		boost::shared_mutex clients_lock_;

		friend client_t;

/* Entire request set */
		std::unordered_map<int32_t, std::weak_ptr<client_t>> requests_;
		boost::shared_mutex requests_lock_;

/* Reuters Wire Format versions. */
		boost::atomic_uint16_t min_rwf_version_;

/* Directory mapped ServiceID */
		boost::atomic_uint16_t service_id_;
public:
unsigned service_state_;
private:
/* RFA can reject new client requests whilst maintaining current connected sessions.
 */
		bool is_accepting_connections_;
		bool is_accepting_requests_;

/* Container of all item streams keyed by symbol name. */
		std::unordered_map<std::string, std::shared_ptr<item_stream_t>> directory_;
		boost::shared_mutex directory_lock_;

/** Performance Counters **/
		boost::posix_time::ptime creation_time_, last_activity_;
		uint32_t cumulative_stats_[PROVIDER_PC_MAX];
		uint32_t snap_stats_[PROVIDER_PC_MAX];
	};

} /* namespace anaguma */

#endif /* PROVIDER_HH_ */

/* eof */