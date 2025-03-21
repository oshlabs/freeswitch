/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Leon de Rooij <leon@exquisip.nl>
 *
 * mod_poc_sctp.c -- SCTP Proof of concept module
 *
 */

#include <switch.h>
#include <switch_types.h>
#include <netinet/sctp.h>
#include <sys/epoll.h>
#include <switch_json.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_poc_sctp_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_poc_sctp_shutdown);
SWITCH_MODULE_DEFINITION(mod_poc_sctp, mod_poc_sctp_load, mod_poc_sctp_shutdown, NULL);

#define SCTP_PORT 5555
#define MAX_EVENTS 10
#define MAX_BUFFER (64 * 1024)  // 64K buffer

static struct {
	switch_memory_pool_t *pool;
	switch_socket_t *socket;
	int epoll_fd;
	int server_fd;
	switch_bool_t running;
	switch_thread_t *thread;
	switch_mutex_t *mutex;
} globals;

static void handle_sctp_notification(union sctp_notification *snp)
{
	switch(snp->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE: {
			char *state_str;
			switch(snp->sn_assoc_change.sac_state) {
				case SCTP_COMM_UP: state_str = "COMM_UP"; break;
				case SCTP_COMM_LOST: state_str = "COMM_LOST"; break;
				case SCTP_RESTART: state_str = "RESTART"; break;
				case SCTP_SHUTDOWN_COMP: state_str = "SHUTDOWN_COMP"; break;
				case SCTP_CANT_STR_ASSOC: state_str = "CANT_START_ASSOC"; break;
				default: state_str = "UNKNOWN"; break;
			}
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
				"SCTP_ASSOC_CHANGE: state=%s(%d), error=%d, outbound=%d, inbound=%d, assoc_id=%d\n",
				state_str,
				snp->sn_assoc_change.sac_state,
				snp->sn_assoc_change.sac_error,
				snp->sn_assoc_change.sac_outbound_streams,
				snp->sn_assoc_change.sac_inbound_streams,
				snp->sn_assoc_change.sac_assoc_id);
			break;
		}
		case SCTP_PEER_ADDR_CHANGE: {
			char *state_str;
			char addr_str[INET6_ADDRSTRLEN];
			struct sockaddr_in *sin;
			struct sockaddr_in6 *sin6;
			void *addr_ptr;
			uint16_t port;

			switch(snp->sn_paddr_change.spc_state) {
				case SCTP_ADDR_AVAILABLE: state_str = "AVAILABLE"; break;
				case SCTP_ADDR_UNREACHABLE: state_str = "UNREACHABLE"; break;
				case SCTP_ADDR_REMOVED: state_str = "REMOVED"; break;
				case SCTP_ADDR_ADDED: state_str = "ADDED"; break;
				case SCTP_ADDR_MADE_PRIM: state_str = "MADE_PRIMARY"; break;
				case SCTP_ADDR_CONFIRMED: state_str = "CONFIRMED"; break;
				default: state_str = "UNKNOWN"; break;
			}

			switch(snp->sn_paddr_change.spc_aaddr.ss_family) {
				case AF_INET:
					sin = (struct sockaddr_in *)&snp->sn_paddr_change.spc_aaddr;
					addr_ptr = &sin->sin_addr;
					port = ntohs(sin->sin_port);
					break;
				case AF_INET6:
					sin6 = (struct sockaddr_in6 *)&snp->sn_paddr_change.spc_aaddr;
					addr_ptr = &sin6->sin6_addr;
					port = ntohs(sin6->sin6_port);
					break;
				default:
					addr_ptr = NULL;
			}

			if (addr_ptr) {
				inet_ntop(snp->sn_paddr_change.spc_aaddr.ss_family,
						addr_ptr, addr_str, sizeof(addr_str));
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
					"SCTP_PEER_ADDR_CHANGE: peer=%s:%d state=%s(%d), error=%d, assoc_id=%d\n",
					addr_str, port,
					state_str,
					snp->sn_paddr_change.spc_state,
					snp->sn_paddr_change.spc_error,
					snp->sn_paddr_change.spc_assoc_id);
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
					"SCTP_PEER_ADDR_CHANGE: unknown address family=%d state=%s(%d), error=%d, assoc_id=%d\n",
					snp->sn_paddr_change.spc_aaddr.ss_family,
					state_str,
					snp->sn_paddr_change.spc_state,
					snp->sn_paddr_change.spc_error,
					snp->sn_paddr_change.spc_assoc_id);
			}
			break;
		}
		case SCTP_REMOTE_ERROR:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
				"SCTP_REMOTE_ERROR: error=%d, assoc_id=%d\n",
				snp->sn_remote_error.sre_error,
				snp->sn_remote_error.sre_assoc_id);
			break;
		case SCTP_SEND_FAILED: {
			char *error_str;
			switch(snp->sn_send_failed.ssf_error) {
				case ETIMEDOUT: error_str = "ETIMEDOUT"; break;
				case ECONNRESET: error_str = "ECONNRESET"; break;
				case EHOSTUNREACH: error_str = "EHOSTUNREACH"; break;
				default: error_str = "UNKNOWN"; break;
			}
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
				"SCTP_SEND_FAILED: error=%s(%d), flags=%x, assoc_id=%d\n",
				error_str,
				snp->sn_send_failed.ssf_error,
				snp->sn_send_failed.ssf_flags,
				snp->sn_send_failed.ssf_assoc_id);
			break;
		}
		case SCTP_SHUTDOWN_EVENT:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
				"SCTP_SHUTDOWN_EVENT: assoc_id=%d\n",
				snp->sn_shutdown_event.sse_assoc_id);
			break;
		default:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
				"Unknown SCTP notification type: %d\n",
				snp->sn_header.sn_type);
	}
}

static void handle_sctp_message(const char *buffer, size_t len, 
							  struct sockaddr_in *peer_addr, socklen_t peer_len,
							  struct sctp_sndrcvinfo *sinfo)
{
	cJSON *json;

	json = cJSON_Parse(buffer);
	if (json) {
		char *pretty = cJSON_Print(json);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
			"SCTP received JSON from %s:%d (size=%ld):\n%s\n",
			inet_ntoa(peer_addr->sin_addr),
			ntohs(peer_addr->sin_port),
			(long)len,
			pretty);
		switch_safe_free(pretty);
		cJSON_Delete(json);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, 
			"SCTP received non-JSON message from %s:%d (size=%ld): %s\n",
			inet_ntoa(peer_addr->sin_addr),
			ntohs(peer_addr->sin_port),
			(long)len,
			buffer);
	}

	// Send "ok" response
	sctp_sendmsg(globals.server_fd, "ok", 2,
		(struct sockaddr*)peer_addr, peer_len,
		sinfo->sinfo_ppid, sinfo->sinfo_flags,
		sinfo->sinfo_stream, 0, 0);
}

static void *SWITCH_THREAD_FUNC sctp_server_thread(switch_thread_t *thread, void *obj)
{
	struct epoll_event events[MAX_EVENTS];
	char buffer[MAX_BUFFER];
	int nfds, i;
	ssize_t len;
	struct sockaddr_in peer_addr;
	socklen_t peer_len;
	struct sctp_sndrcvinfo sinfo;
	int msg_flags;

	memset(events, 0, sizeof(events));
	memset(&peer_addr, 0, sizeof(peer_addr));
	memset(&sinfo, 0, sizeof(sinfo));

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "starting sctp_server_thread\n");

	while (globals.running) {
		nfds = epoll_wait(globals.epoll_fd, events, MAX_EVENTS, 1000);
		if (nfds < 0) {
			if (errno != EINTR) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
					"epoll_wait failed: %s\n", strerror(errno));
			}
			continue;
		}

		for (i = 0; i < nfds; i++) {
			if (events[i].data.fd == globals.server_fd) {
				peer_len = sizeof(peer_addr);
				msg_flags = 0;

				len = sctp_recvmsg(globals.server_fd, buffer, sizeof(buffer),
					(struct sockaddr*)&peer_addr, &peer_len,
					&sinfo, &msg_flags);

				if (len < 0) {
					if (errno != EAGAIN && errno != EWOULDBLOCK) {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
							"recvmsg error: %s\n", strerror(errno));
					}
					continue;
				}

				buffer[len] = '\0';

				if (msg_flags & MSG_NOTIFICATION) {
					handle_sctp_notification((union sctp_notification *)buffer);
				} else {
					handle_sctp_message(buffer, len, &peer_addr, peer_len, &sinfo);
				}
			}
		}
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "exiting sctp_server_thread\n");
	return NULL;
}

static switch_status_t init_sctp_server(void)
{
	int flags;
	struct sockaddr_in addr;
	struct sctp_initmsg initmsg;
	struct sctp_event_subscribe events;
	struct epoll_event ev;

	globals.epoll_fd = epoll_create1(0);
	if (globals.epoll_fd < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create epoll: %s\n", strerror(errno));
		return SWITCH_STATUS_FALSE;
	}

	globals.server_fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
	if (globals.server_fd < 0) {
		close(globals.epoll_fd);
		return SWITCH_STATUS_FALSE;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "SCTP server socket %d initialized\n", globals.server_fd);

	// Set SCTP INIT options
	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.sinit_num_ostreams = 5;
	initmsg.sinit_max_instreams = 5;
	initmsg.sinit_max_attempts = 4;
	if (setsockopt(globals.server_fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to set SCTP init options: %s\n", strerror(errno));
		close(globals.server_fd);
		close(globals.epoll_fd);
		return SWITCH_STATUS_FALSE;
	}

	// Enable SCTP event notifications
	memset(&events, 0, sizeof(events));
	events.sctp_data_io_event = 1;
	events.sctp_association_event = 1;
	events.sctp_address_event = 1;
	events.sctp_send_failure_event = 1;
	events.sctp_peer_error_event = 1;
	events.sctp_shutdown_event = 1;
	events.sctp_partial_delivery_event = 1;
	events.sctp_adaptation_layer_event = 1;

	if (setsockopt(globals.server_fd, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof(events)) < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to set SCTP event options: %s\n", strerror(errno));
		close(globals.server_fd);
		close(globals.epoll_fd);
		return SWITCH_STATUS_FALSE;
	}

	// Set non-blocking
	flags = fcntl(globals.server_fd, F_GETFL, 0);
	fcntl(globals.server_fd, F_SETFL, flags | O_NONBLOCK);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(SCTP_PORT);

	if (bind(globals.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to bind SCTP socket: %s\n", strerror(errno));
		close(globals.server_fd);
		close(globals.epoll_fd);
		return SWITCH_STATUS_FALSE;
	}

	if (listen(globals.server_fd, 5) < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to listen on SCTP socket: %s\n", strerror(errno));
		close(globals.server_fd);
		close(globals.epoll_fd);
		return SWITCH_STATUS_FALSE;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = globals.server_fd;
	if (epoll_ctl(globals.epoll_fd, EPOLL_CTL_ADD, globals.server_fd, &ev) < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to add SCTP socket to epoll: %s\n", strerror(errno));
		close(globals.server_fd);
		close(globals.epoll_fd);
		return SWITCH_STATUS_FALSE;
	}

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_STANDARD_API(sctp_send_function)
{
	if (!zstr(cmd)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Sending SCTP message: %s\n", cmd);
		// Here you would iterate through connected clients and send the message
		// For now, just log it
		stream->write_function(stream, "+OK Message queued for sending\n");
	} else {
		stream->write_function(stream, "-ERR No message specified\n");
	}
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_poc_sctp_load)
{
	switch_api_interface_t *api_interface;
	switch_threadattr_t *thd_attr = NULL;
	
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	globals.pool = pool;

	SWITCH_ADD_API(api_interface, "sctp_send", "Send SCTP Message", sctp_send_function, "<message>");

	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, globals.pool);
	globals.running = SWITCH_TRUE;

	if (init_sctp_server() != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_FALSE;
	}

	switch_threadattr_create(&thd_attr, globals.pool);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&globals.thread, thd_attr, sctp_server_thread, NULL, globals.pool);

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_poc_sctp_shutdown)
{
	switch_status_t status;
	globals.running = SWITCH_FALSE;
	
	if (globals.thread) {
		switch_thread_join(&status, globals.thread);
	}
	
	if (globals.epoll_fd >= 0) {
		close(globals.epoll_fd);
	}
	
	if (globals.server_fd >= 0) {
		close(globals.server_fd);
	}

	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
