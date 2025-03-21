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
 * mod_poc_dialog.c -- Dialog Proof of concept module
 *
 */

#include <switch.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_poc_dialog_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_poc_dialog_shutdown);
SWITCH_MODULE_DEFINITION(mod_poc_dialog, mod_poc_dialog_load, mod_poc_dialog_shutdown, NULL);

struct dialog_locals {
	char *id;
	switch_thread_t *thread;
	switch_queue_t *message_queue;
	switch_memory_pool_t *pool;
	switch_mutex_t *mutex;
	switch_thread_rwlock_t *rwlock;    // Fixed: Using switch_thread_rwlock_t
	switch_bool_t running;
};

static struct {
	switch_memory_pool_t *pool;
	switch_socket_t *socket;
	int epoll_fd;
	int server_fd;
	switch_bool_t running;
	switch_thread_t *thread;
	switch_mutex_t *mutex;
	switch_hash_t *dialogs;          // Hash table for dialog threads
	switch_mutex_t *dialogs_mutex;   // Mutex for dialog hash table access
} globals;

static void *SWITCH_THREAD_FUNC dialog_thread_run(switch_thread_t *thread, void *obj)
{
	struct dialog_thread *dialog = (struct dialog_thread *)obj;
	void *pop;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
		"Dialog thread starting for id: %s\n", dialog->id);

	while (dialog->running) {
		if (switch_queue_pop(dialog->message_queue, &pop) == SWITCH_STATUS_SUCCESS) {
			char *msg;
			msg = (char *)pop;
			
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
				"Dialog %s processing message:\n%s\n", dialog->id, msg);
			switch_safe_free(msg);
		}
	}

	// Get write lock before cleanup - this ensures no readers are accessing us
	switch_thread_rwlock_wrlock(dialog->rwlock);

	// Remove ourselves from the hash table
	switch_mutex_lock(globals.dialogs_mutex);
	switch_core_hash_delete(globals.dialogs, dialog->id);
	switch_mutex_unlock(globals.dialogs_mutex);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
		"Dialog thread ending for id: %s\n", dialog->id);

	// Clean up our memory pool which will free all allocated memory
	switch_core_destroy_memory_pool(&dialog->pool);
	return NULL;
}

static struct dialog_thread *create_dialog_thread(const char *id)
{
	struct dialog_thread *dialog;
	switch_threadattr_t *thd_attr = NULL;
	switch_memory_pool_t *pool;

	// Create memory pool for this dialog
	if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
			"Failed to create memory pool for dialog: %s\n", id);
		return NULL;
	}

	// Allocate dialog structure
	dialog = switch_core_alloc(pool, sizeof(struct dialog_thread));
	dialog->pool = pool;
	dialog->id = switch_core_strdup(pool, id);
	dialog->running = SWITCH_TRUE;

	// Initialize mutex, rwlock and message queue
	switch_mutex_init(&dialog->mutex, SWITCH_MUTEX_NESTED, dialog->pool);
	switch_thread_rwlock_create(&dialog->rwlock, dialog->pool);
	if (switch_queue_create(&dialog->message_queue, 100, dialog->pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
			"Failed to create message queue for dialog: %s\n", id);
		switch_core_destroy_memory_pool(&pool);
		return NULL;
	}

	// Create and start the dialog thread
	switch_threadattr_create(&thd_attr, dialog->pool);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	if (switch_thread_create(&dialog->thread, thd_attr, dialog_thread_run, dialog, dialog->pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
			"Failed to create thread for dialog: %s\n", id);
		switch_core_destroy_memory_pool(&pool);
		return NULL;
	}

	return dialog;
}

static struct dialog_thread *find_dialog(const char *id)
{
	struct dialog_locals *locals = NULL;

	switch_mutex_lock(globals.dialogs_mutex);
	if ((dialog = switch_core_hash_find(globals.dialogs, id))) {
		if (switch_thread_rwlock_tryrdlock(dialog->rwlock) != SWITCH_STATUS_SUCCESS) {
			dialog = NULL;
		}
	}
	switch_mutex_unlock(globals.dialogs_mutex);

	return dialog;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_poc_dialog_load)
{
	switch_api_interface_t *api_interface;
	switch_threadattr_t *thd_attr = NULL;
	
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	globals.pool = pool;

	// Initialize dialog hash table
	switch_mutex_init(&globals.dialogs_mutex, SWITCH_MUTEX_NESTED, globals.pool);
	switch_core_hash_init(&globals.dialogs);

	globals.running = SWITCH_TRUE;

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_poc_dialog_shutdown)
{
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
