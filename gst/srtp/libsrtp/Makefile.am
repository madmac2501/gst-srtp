
noinst_LTLIBRARIES = libsrtp.la

# libcrypt (the crypto engine) 
ciphers = crypto/cipher/cipher.c crypto/cipher/null_cipher.c      \
          crypto/cipher/aes.c crypto/cipher/aes_icm.c             \
          crypto/cipher/aes_cbc.c

hashes  = crypto/hash/null_auth.c crypto/hash/sha1.c \
          crypto/hash/hmac.c crypto/hash/auth.c # crypto/hash/tmmhv2.c 

replay  = crypto/replay/rdb.c crypto/replay/rdbx.c               \
          crypto/replay/ut_sim.c 

math    = crypto/math/datatypes.c crypto/math/stat.c

ust     = crypto/ust/ust.c 

if SRTP_RNG_LINUX
main_rng = crypto/rng/rand_linux_kernel.c
else
main_rng = crypto/rng/rand_source.c
endif

rng     = $(main_rng) crypto/rng/prng.c crypto/rng/ctr_prng.c

err     = crypto/kernel/err.c

kernel  = crypto/kernel/crypto_kernel.c  crypto/kernel/alloc.c   \
          crypto/kernel/key.c $(rng) $(err) # $(ust) 

# libsrtp.la (implements srtp processing)

libsrtp_la_SOURCES = $(ciphers) $(hashes) $(math) $(stat) $(kernel) $(replay) \
	srtp/srtp.c 

AM_CFLAGS = -I$(srcdir) -I$(srcdir)/include

# These should be make into proper "check_PROGRAMS" tests

# crypto_testapp = crypto/test/aes_calc crypto/test/cipher_driver \
# 	crypto/test/datatypes_driver crypto/test/kernel_driver \
# 	crypto/test/rand_gen crypto/test/sha1_driver \
# 	crypto/test/stat_driver

# testapp = $(crypto_testapp) test/srtp_driver test/replay_driver \
# 	  test/roc_driver test/rdbx_driver test/rtpw \
# 	  test/dtls_srtp_driver

# test_rtpw_SOURCES = test/rtpw.c test/rtp.c test/getopt_s.c
# test_srtp_driver_SOURCES = test/srtp_driver.c test/getopt_s.c
# test_rdbx_driver_SOURCES = test/rdbx_driver.c test/getopt_s.c
# test_dtls_srtp_driver_SOURCES = test/dtls_srtp_driver.c test/getopt_s.c


# noinst_PROGRAMS= $(crypto_testapp) $(testapp)
