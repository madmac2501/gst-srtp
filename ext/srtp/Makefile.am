plugin_LTLIBRARIES = libgstsrtp.la

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
	$(built_sources) \
	$(built_headers)

# flags used to compile this plugin
# add other _CFLAGS and _LIBS as needed
libgstsrtp_la_CFLAGS = $(GST_PLUGINS_BASE_CFLAGS) $(GST_CFLAGS)
libgstsrtp_la_LIBADD = $(GST_PLUGINS_BASE_LIBS) \
		-lgstrtp-@GST_MAJORMINOR@ \
		$(GST_BASE_LIBS) $(GST_LIBS) $(SRTP_LIBS)
libgstsrtp_la_LDFLAGS = $(GST_PLUGIN_LDFLAGS)
libgstsrtp_la_LIBTOOLFLAGS = --tag=disable-static

# headers we need but don't want installed
noinst_HEADERS = \
  gstsrtpsend.h \
  gstsrtprecv.h

EXTRA_DIST = gstsrtp-marshal.list
CLEANFILES = $(BUILT_SOURCES)

include $(top_srcdir)/common/gst-glib-gen.mak
