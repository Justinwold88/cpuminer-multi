
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

EXTRA_DIST	= autogen.sh example-cfg.json nomacro.pl

SUBDIRS		= compat

AM_CPPFLAGS	= $(JANSSON_INCLUDES) $(LIBCURL_CFLAGS)
AM_CFLAGS	= $(PTHREAD_FLAGS) -fno-strict-aliasing

# All proof-of-work code lives in one library so that the miner and the
# test programs link exactly the same objects.
noinst_LIBRARIES = libalgos.a

libalgos_a_SOURCES = \
		  sha2.c \
		  scrypt.c \
		  keccak.c \
		  heavy.c \
		  quark.c \
		  skein.c \
		  ink.c \
		  blake.c \
		  cryptonight.c \
		  fresh.c \
		  x11.c \
		  x13.c \
		  x14.c \
		  x15.c \
		  sha3/sph_keccak.c \
		  sha3/sph_hefty1.c \
		  sha3/sph_groestl.c \
		  sha3/sph_skein.c \
		  sha3/sph_bmw.c \
		  sha3/sph_jh.c \
		  sha3/sph_shavite.c \
		  sha3/sph_blake.c \
		  sha3/sph_luffa.c \
		  sha3/sph_cubehash.c \
		  sha3/sph_simd.c \
		  sha3/sph_echo.c \
		  sha3/sph_hamsi.c \
		  sha3/sph_fugue.c \
		  sha3/sph_shabal.c \
		  sha3/sph_whirlpool.c \
		  crypto/oaes_lib.c \
		  crypto/c_keccak.c \
		  crypto/c_groestl.c \
		  crypto/c_blake256.c \
		  crypto/c_jh.c \
		  crypto/c_skein.c \
		  crypto/hash.c \
		  crypto/aesb.c

if USE_ASM
if ARCH_x86
libalgos_a_SOURCES += sha2-x86.S scrypt-x86.S aesb-x86.S crypto/aesb-x86-impl.c
endif
if ARCH_x86_64
libalgos_a_SOURCES += sha2-x64.S scrypt-x64.S aesb-x64.S
endif
if ARCH_ARM
libalgos_a_SOURCES += sha2-arm.S scrypt-arm.S aesb-arm.S crypto/aesb-x86-impl.c
endif
endif

bin_PROGRAMS	= minerd

dist_man_MANS	= minerd.1

minerd_SOURCES	= elist.h \
		  miner.h \
		  compat.h \
		  cpu-miner.c \
		  util.c

minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= libalgos.a $(LIBCURL_LIBS) $(JANSSON_LIBS) $(PTHREAD_LIBS) $(WS2_LIBS)
