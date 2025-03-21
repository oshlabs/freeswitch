include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_poc_dlg

mod_LTLIBRARIES = mod_poc_dlg.la
mod_poc_dlg_la_SOURCES  = mod_poc_dlg.c
mod_poc_dlg_la_CFLAGS   = $(AM_CFLAGS) -std=c17
mod_poc_dlg_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_poc_dlg_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
