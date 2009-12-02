noinst_PROGRAMS = server-srtp client-srtp

server_srtp_SOURCES = server-srtp.c
server_srtp_CFLAGS = $(GST_CFLAGS)
server_srtp_LDADD = $(GST_LIBS) $(LIBM)

client_srtp_SOURCES = client-srtp.c
client_srtp_CFLAGS = $(GST_CFLAGS)
client_srtp_LDADD = $(GST_LIBS) $(LIBM)

noinst_SCRIPTS=client-srtp.sh \
               server-srtp.sh

EXTRA_DIST= $(noinst_SCRIPTS)
