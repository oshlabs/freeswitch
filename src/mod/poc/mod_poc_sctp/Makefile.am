include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_poc_sctp

mod_LTLIBRARIES = mod_poc_sctp.la
mod_poc_sctp_la_SOURCES  = mod_poc_sctp.c
mod_poc_sctp_la_CFLAGS   = $(AM_CFLAGS)
mod_poc_sctp_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_poc_sctp_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
