# plugindir is set in configure

##############################################################################
# change libgstplugin.la to something more suitable, e.g. libmysomething.la  #
##############################################################################
plugin_LTLIBRARIES = libgstsrtp.la

##############################################################################
# for the next set of variables, rename the prefix if you renamed the .la,   #
#  e.g. libgstplugin_la_SOURCES => libmysomething_la_SOURCES                 #
#       libgstplugin_la_CFLAGS  => libmysomething_la_CFLAGS                  #
#       libgstplugin_la_LIBADD  => libmysomething_la_LIBADD                  #
#       libgstplugin_la_LDFLAGS => libmysomething_la_LDFLAGS                 #
##############################################################################

srtp_headers = 		\
	gstsrtprecv.h   \
	gstsrtpsend.h

glib_enum_headers=$(srtp_headers)
glib_enum_define=GST_SRTP
glib_gen_prefix=gst_srtp
glib_gen_basename=gstsrtp

built_sources =			\
	gstsrtp-marshal.c	\
	gstsrtp-enumtypes.c

built_headers = 		\
	gstsrtp-marshal.h	\
	gstsrtp-enumtypes.h

BUILT_SOURCES = $(built_sources) $(built_headers)

# sources used to compile this plug-in
libgstsrtp_la_SOURCES = \
  gstsrtp.c \
  gstsrtpsend.c \
  gstsrtprecv.c

nodist_libgstsrtp_la_SOURCES = \
	$(built_sources)

nodist_libgstsrtp_la_HEADERS = \
	gstsrtp-enumtypes.h

# flags used to compile this plugin
# add other _CFLAGS and _LIBS as needed
libgstsrtp_la_CFLAGS = /usr/lib $(GST_CFLAGS)
libgstsrtp_la_LIBADD = $(GST_LIBS) $(GST_PLUGINS_BASE_LIBS) $(GSTCTRL_LIBS) $(GSTRTP_LIBS) $(GSTPB_BASE_LIBS) libsrtp/libsrtp.a
libgstsrtp_la_LDFLAGS = $(GST_PLUGIN_LDFLAGS)
libgstsrtp_la_LIBTOOLFLAGS = --tag=disable-static

# headers we need but don't want installed
noinst_HEADERS = \
  gstsrtpsend.h \
  gstsrtprecv.h

EXTRA_DIST = gstsrtp-marshal.list
CLEANFILES = $(BUILT_SOURCES)

include $(top_srcdir)/common/gst-glib-gen.mak

SUBDIRS = libsrtp
DIST_SUBDIRS = libsrtp
