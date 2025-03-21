include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_poc_dialog

mod_LTLIBRARIES = mod_poc_dialog.la
mod_poc_dialog_la_SOURCES  = mod_poc_dialog.c
mod_poc_dialog_la_CFLAGS   = $(AM_CFLAGS) -std=c17
mod_poc_dialog_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_poc_dialog_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
