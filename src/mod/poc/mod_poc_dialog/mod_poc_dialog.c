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

typedef struct {
	char *id;
	switch_thread_t *thread;
	switch_queue_t *message_queue;
	switch_memory_pool_t *pool;
	switch_thread_rwlock_t *rwlock;
	switch_bool_t running;
} dialog_locals_t;

static struct {
	switch_memory_pool_t *pool;
	switch_hash_t *dialogs;          // Hash table for dialog threads
	switch_mutex_t *dialogs_mutex;   // Mutex for dialog hash table access
} globals;

static void *SWITCH_THREAD_FUNC dialog_thread_run(switch_thread_t *thread, void *obj)
{
	dialog_locals_t *locals = (dialog_locals_t *)obj;
	void *pop;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
		"Dialog thread starting for id: %s\n", locals->id);

	while (locals->running) {
		if (switch_queue_pop(locals->message_queue, &pop) == SWITCH_STATUS_SUCCESS) {
			char *msg = (char *)pop;
			
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
				"Dialog %s processing message: %s\n", locals->id, msg);
			switch_safe_free(msg);
		}
	}
	
	// Get write lock to ensure no new readers
	switch_thread_rwlock_wrlock(locals->rwlock);
	
	// Remove from hash while holding write lock
	switch_mutex_lock(globals.dialogs_mutex);
	switch_core_hash_delete(globals.dialogs, locals->id);
	switch_mutex_unlock(globals.dialogs_mutex);
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
		"Dialog thread ending for id: %s\n", locals->id);

	// Safe to destroy pool - we have write lock and dialog is removed from hash
	switch_core_destroy_memory_pool(&locals->pool);
	
	// Keep rwlock held until thread exits
	return NULL;
}

static dialog_locals_t *find_dialog(const char *id)
{
	dialog_locals_t *locals = NULL;
	
	switch_mutex_lock(globals.dialogs_mutex);
	if ((locals = switch_core_hash_find(globals.dialogs, id))) {
		if (switch_thread_rwlock_tryrdlock(locals->rwlock) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO,
				"Found dialog but failed to lock rwlock: %s\n", id);
			locals = NULL;
		}
	}
	switch_mutex_unlock(globals.dialogs_mutex);
	
	return locals;
}

static dialog_locals_t *create_dialog_thread(const char *id)
{
	dialog_locals_t *locals;
	switch_threadattr_t *thd_attr = NULL;
	switch_memory_pool_t *pool;

	// Create memory pool for this dialog
	if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
			"Failed to create memory pool for dialog: %s\n", id);
		return NULL;
	}

	// Allocate dialog structure
	locals = switch_core_alloc(pool, sizeof(dialog_locals_t));
	locals->pool = pool;
	locals->id = switch_core_strdup(pool, id);
	locals->running = SWITCH_TRUE;

	// Initialize rwlock and message queue
	switch_thread_rwlock_create(&locals->rwlock, locals->pool);
	if (switch_queue_create(&locals->message_queue, 100, locals->pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
			"Failed to create message queue for dialog: %s\n", id);
		switch_core_destroy_memory_pool(&pool);
		return NULL;
	}

	// Create and start the dialog thread
	switch_threadattr_create(&thd_attr, locals->pool);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	if (switch_thread_create(&locals->thread, thd_attr, dialog_thread_run, locals, locals->pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
			"Failed to create thread for dialog: %s\n", id);
		switch_core_destroy_memory_pool(&pool);
		return NULL;
	}

	return locals;
}

SWITCH_STANDARD_API(dialog_api_function)
{
	char *argv[10] = { 0 };
	int argc;
	char *mycmd = NULL;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	if (zstr(cmd)) {
		stream->write_function(stream, "-ERR Invalid input\n");
		return SWITCH_STATUS_SUCCESS;
	}

	mycmd = strdup(cmd);
	argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));

	if (argc < 2) {
		stream->write_function(stream, "-ERR Invalid input\n");
		goto done;
	}

	if (!strcasecmp(argv[0], "create")) {
		dialog_locals_t *dialog;

		// Check if dialog already exists
		if (find_dialog(argv[1])) {
			stream->write_function(stream, "-ERR Dialog %s already exists\n", argv[1]);
			goto done;
		}

		// Create new dialog thread
		dialog = create_dialog_thread(argv[1]);
		if (!dialog) {
			stream->write_function(stream, "-ERR Failed to create dialog %s\n", argv[1]);
			goto done;
		}

		// Add to hash table
		switch_mutex_lock(globals.dialogs_mutex);
		switch_core_hash_insert(globals.dialogs, dialog->id, dialog);
		switch_mutex_unlock(globals.dialogs_mutex);

		stream->write_function(stream, "+OK Dialog %s created\n", argv[1]);
	}
	else if (!strcasecmp(argv[0], "send")) {
		dialog_locals_t *dialog;
		char *message;

		if (argc < 3) {
			stream->write_function(stream, "-ERR Missing message\n");
			goto done;
		}

		dialog = find_dialog(argv[1]);
		if (!dialog) {
			stream->write_function(stream, "-ERR Dialog %s not found\n", argv[1]);
			goto done;
		}

		// Allocate message from heap instead of pool
		message = strdup(argv[2]);
		if (!message) {
			stream->write_function(stream, "-ERR Memory allocation failed\n");
			switch_thread_rwlock_unlock(dialog->rwlock);
			goto done;
		}
		
		// Queue message
		if (switch_queue_trypush(dialog->message_queue, message) != SWITCH_STATUS_SUCCESS) {
			switch_safe_free(message);  // Free message if queue push failed
			stream->write_function(stream, "-ERR Failed to queue message\n");
		} else {
			stream->write_function(stream, "+OK Message queued\n");
		}

		// Release read lock
		switch_thread_rwlock_unlock(dialog->rwlock);
	}
	else {
		stream->write_function(stream, "-ERR Unknown command: %s\n", argv[0]);
	}

done:
	switch_safe_free(mycmd);
	return status;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_poc_dialog_load)
{
	switch_api_interface_t *api_interface;
	
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	globals.pool = pool;

	// Initialize dialog hash table
	switch_mutex_init(&globals.dialogs_mutex, SWITCH_MUTEX_NESTED, globals.pool);
	switch_core_hash_init(&globals.dialogs);

	SWITCH_ADD_API(api_interface, "dialog", "Dialog testing", dialog_api_function, "<cmd> <id> [<args>]");

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_poc_dialog_shutdown)
{
	switch_hash_index_t *hi;
	void *val;
	dialog_locals_t *dialog;

	switch_mutex_lock(globals.dialogs_mutex);
	for (hi = switch_core_hash_first(globals.dialogs); hi; hi = switch_core_hash_next(&hi)) {
		switch_core_hash_this(hi, NULL, NULL, &val);
		dialog = (dialog_locals_t *)val;
		dialog->running = SWITCH_FALSE;
	}
	switch_mutex_unlock(globals.dialogs_mutex);

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
