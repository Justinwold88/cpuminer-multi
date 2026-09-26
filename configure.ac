AC_PREREQ([2.69])
AC_INIT([cpuminer-multi], [1.1.0-dev],
	[https://github.com/Justinwold88/cpuminer-multi/issues],
	[cpuminer-multi],
	[https://github.com/Justinwold88/cpuminer-multi])
AC_CONFIG_SRCDIR([cpu-miner.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([cpuminer-config.h])

m4_ifndef([PKG_PROG_PKG_CONFIG],
	[m4_fatal([pkg.m4 is missing: install pkg-config (or pkgconf) and re-run ./autogen.sh])])

dnl Checks for programs
AC_PROG_CC
AM_PROG_AS
AM_PROG_AR
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

dnl Checks for header files
AC_CHECK_HEADERS([sys/endian.h sys/param.h syslog.h])
# sys/sysctl.h requires sys/types.h on FreeBSD
# sys/sysctl.h requires sys/param.h on OpenBSD
AC_CHECK_HEADERS([sys/sysctl.h], [], [],
[#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
])

AC_CHECK_DECLS([be32dec, le32dec, be32enc, le32enc], [], [],
[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
])

AC_FUNC_ALLOCA
AC_CHECK_FUNCS([getopt_long])

dnl Target CPU and OS (the machine the miner will run on is $host)
have_x86=false
have_x86_64=false
have_arm=false
have_aarch64=false
case $host_cpu in
  i?86)
    have_x86=true
    ;;
  x86_64|amd64)
    have_x86_64=true
    ;;
  aarch64|arm64)
    have_aarch64=true
    ;;
  arm*)
    have_arm=true
    ;;
esac

have_win32=false
PTHREAD_FLAGS="-pthread"
WS2_LIBS=""
case $host_os in
  mingw*|cygwin*|msys*)
    have_win32=true
    PTHREAD_FLAGS=""
    WS2_LIBS="-lws2_32"
    ;;
esac

AC_ARG_ENABLE([assembly],
  AS_HELP_STRING([--disable-assembly], [disable assembly-language routines]))
if test "x$enable_assembly" != xno; then
  AC_DEFINE([USE_ASM], [1], [Define to 1 if assembly routines are wanted.])
fi

if test "x$enable_assembly" != xno && test "x$have_x86_64" = xtrue
then
  AC_MSG_CHECKING(whether we can compile AVX code)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vmovdqa %ymm0, %ymm1");])],
    AC_DEFINE(USE_AVX, 1, [Define to 1 if AVX assembly is available.])
    AC_MSG_RESULT(yes)
    AC_MSG_CHECKING(whether we can compile XOP code)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vprotd \$7, %xmm0, %xmm1");])],
      AC_DEFINE(USE_XOP, 1, [Define to 1 if XOP assembly is available.])
      AC_MSG_RESULT(yes)
    ,
      AC_MSG_RESULT(no)
      AC_MSG_WARN([The assembler does not support the XOP instruction set.])
    )
    AC_MSG_CHECKING(whether we can compile AVX2 code)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,[asm ("vpaddd %ymm0, %ymm1, %ymm2");])],
      AC_DEFINE(USE_AVX2, 1, [Define to 1 if AVX2 assembly is available.])
      AC_MSG_RESULT(yes)
    ,
      AC_MSG_RESULT(no)
      AC_MSG_WARN([The assembler does not support the AVX2 instruction set.])
    )
  ,
    AC_MSG_RESULT(no)
    AC_MSG_WARN([The assembler does not support the AVX instruction set.])
  )
fi

if test "x$enable_assembly" != xno && test "x$have_x86" = xtrue; then
  dnl The 32-bit x86 assembly is not position independent: in a PIE (the
  dnl default with most compilers now) it needs text relocations, which
  dnl some linkers refuse.
  AC_MSG_CHECKING([whether the linker accepts -no-pie])
  save_LDFLAGS=$LDFLAGS
  LDFLAGS="$LDFLAGS -no-pie"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no]); LDFLAGS=$save_LDFLAGS])
fi

AC_CHECK_LIB([pthread], [pthread_create], PTHREAD_LIBS="-lpthread",
  AC_CHECK_LIB([pthreadGC2], [pthread_create], PTHREAD_LIBS="-lpthreadGC2",
    AC_CHECK_LIB([pthreadGC1], [pthread_create], PTHREAD_LIBS="-lpthreadGC1",
      AC_CHECK_LIB([pthreadGC], [pthread_create], PTHREAD_LIBS="-lpthreadGC"
))))

AC_MSG_CHECKING(whether __uint128_t is supported)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([static __uint128_t i = 100;])],
      AC_DEFINE(USE_INT128, 1, [Define if __uint128_t is available])
      AC_MSG_RESULT(yes)
    ,
      AC_MSG_RESULT(no)
)

PKG_CHECK_MODULES([LIBCURL], [libcurl >= 7.15.2], [],
  [dnl no pkg-config file: e.g. the libcurl that comes with macOS
   AC_CHECK_HEADER([curl/curl.h], [],
     [AC_MSG_ERROR([libcurl not found: install its development package (Debian/Ubuntu: libcurl4-openssl-dev, Fedora: libcurl-devel, MSYS2: mingw-w64-ucrt-x86_64-curl)])])
   AC_CHECK_LIB([curl], [curl_easy_init], [LIBCURL_LIBS=-lcurl],
     [AC_MSG_ERROR([libcurl not found: install its development package (Debian/Ubuntu: libcurl4-openssl-dev, Fedora: libcurl-devel, MSYS2: mingw-w64-ucrt-x86_64-curl)])])])
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.7], [],
  [AC_MSG_ERROR([jansson 2.7 or newer not found: install its development package (Debian/Ubuntu: libjansson-dev, Fedora: jansson-devel, macOS: brew install jansson, MSYS2: mingw-w64-ucrt-x86_64-jansson)])])

AM_CONDITIONAL([HAVE_WINDOWS], [test x$have_win32 = xtrue])
AM_CONDITIONAL([USE_ASM], [test x$enable_assembly != xno])
AM_CONDITIONAL([ARCH_x86], [test x$have_x86 = xtrue])
AM_CONDITIONAL([ARCH_x86_64], [test x$have_x86_64 = xtrue])
AM_CONDITIONAL([ARCH_ARM], [test x$have_arm = xtrue])
AM_CONDITIONAL([ARCH_AARCH64], [test x$have_aarch64 = xtrue])

AC_SUBST(PTHREAD_FLAGS)
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(WS2_LIBS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
