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

SWITCH_MODULE_LOAD_FUNCTION(mod_poc_sctp_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_poc_sctp_shutdown);
SWITCH_MODULE_DEFINITION(mod_poc_sctp, mod_poc_sctp_load, mod_poc_sctp_shutdown, NULL);

#define SCTP_PORT 5555
#define MAX_EVENTS 10
#define MAX_BUFFER 1024

static struct {
	switch_memory_pool_t *pool;
	switch_socket_t *socket;
	int epoll_fd;
	int server_fd;
	switch_bool_t running;
	switch_thread_t *thread;
	switch_mutex_t *mutex;
} globals;

#if 0
static switch_status_t sctp_send_message(int client_fd, const char *message) {
	ssize_t sent = sctp_sendmsg(client_fd, message, strlen(message), 
							   NULL, 0, 0, 0, 0, 0, 0);
	return (sent > 0) ? SWITCH_STATUS_SUCCESS : SWITCH_STATUS_FALSE;
}
#endif

static void *SWITCH_THREAD_FUNC sctp_server_thread(switch_thread_t *thread, void *obj)
{
	struct epoll_event events[MAX_EVENTS];
	char buffer[MAX_BUFFER];
	int nfds, i;
	ssize_t len;

	while (globals.running) {
		nfds = epoll_wait(globals.epoll_fd, events, MAX_EVENTS, -1);
		if (nfds < 0) continue;

		for (i = 0; i < nfds; i++) {
			if (events[i].data.fd == globals.server_fd) {
				struct sockaddr_in peer_addr;
				socklen_t peer_len = sizeof(peer_addr);
				struct sctp_sndrcvinfo sinfo;
				int flags;

				while ((len = sctp_recvmsg(globals.server_fd, buffer, MAX_BUFFER-1,
										   (struct sockaddr*)&peer_addr, &peer_len,
										   &sinfo, &flags)) > 0) {
					buffer[len] = '\0';
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
									  "SCTP received: %s\n", buffer);

					// Respond to exact peer (mandatory!)
					sctp_sendmsg(globals.server_fd, "ok", 2,
								 (struct sockaddr*)&peer_addr, peer_len,
								 sinfo.sinfo_ppid, sinfo.sinfo_flags, sinfo.sinfo_stream, 0, 0);
				}

				if (len < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
									  "recvmsg error: %s\n", strerror(errno));
				}



			}
		}
	}

	return NULL;
}

static switch_status_t init_sctp_server(void)
{
	int flags;
	struct sockaddr_in addr;
	struct epoll_event ev;

	globals.server_fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
	if (globals.server_fd < 0) return SWITCH_STATUS_FALSE;

	// Set non-blocking
	flags = fcntl(globals.server_fd, F_GETFL, 0);
	fcntl(globals.server_fd, F_SETFL, flags | O_NONBLOCK);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(SCTP_PORT);

	if (bind(globals.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(globals.server_fd);
		return SWITCH_STATUS_FALSE;
	}

	//if (listen(globals.server_fd, 5) < 0) {
	//	close(globals.server_fd);
	//	return SWITCH_STATUS_FALSE;
	//}

	globals.epoll_fd = epoll_create1(0);
	if (globals.epoll_fd < 0) {
		close(globals.server_fd);
		return SWITCH_STATUS_FALSE;
	}

	ev.events = EPOLLIN; // add later: | EPOLLET;
	ev.data.fd = globals.server_fd;
	epoll_ctl(globals.epoll_fd, EPOLL_CTL_ADD, globals.server_fd, &ev);

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
