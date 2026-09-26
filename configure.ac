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

AC_CHECK_LIB(jansson, json_loads, request_jansson=false, request_jansson=true)
AC_CHECK_LIB([pthread], [pthread_create], PTHREAD_LIBS="-lpthread",
  AC_CHECK_LIB([pthreadGC2], [pthread_create], PTHREAD_LIBS="-lpthreadGC2",
    AC_CHECK_LIB([pthreadGC1], [pthread_create], PTHREAD_LIBS="-lpthreadGC1",
      AC_CHECK_LIB([pthreadGC], [pthread_create], PTHREAD_LIBS="-lpthreadGC"
))))

AC_CHECK_LIB([crypto], [SHA256_Init], [], [AC_MSG_FAILURE([could not find crypto])])

AC_MSG_CHECKING(whether __uint128_t is supported)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([static __uint128_t i = 100;])],
      AC_DEFINE(USE_INT128, 1, [Define if __uint128_t is available])
      AC_MSG_RESULT(yes)
    ,
      AC_MSG_RESULT(no)
)

PKG_CHECK_MODULES([LIBCURL], [libcurl >= 7.15.2])

AM_CONDITIONAL([WANT_JANSSON], [test x$request_jansson = xtrue])
AM_CONDITIONAL([HAVE_WINDOWS], [test x$have_win32 = xtrue])
AM_CONDITIONAL([USE_ASM], [test x$enable_assembly != xno])
AM_CONDITIONAL([ARCH_x86], [test x$have_x86 = xtrue])
AM_CONDITIONAL([ARCH_x86_64], [test x$have_x86_64 = xtrue])
AM_CONDITIONAL([ARCH_ARM], [test x$have_arm = xtrue])
AM_CONDITIONAL([ARCH_AARCH64], [test x$have_aarch64 = xtrue])

if test x$request_jansson = xtrue
then
	JANSSON_LIBS="compat/jansson/libjansson.a"
else
	JANSSON_LIBS=-ljansson
fi

AC_SUBST(JANSSON_LIBS)
AC_SUBST(PTHREAD_FLAGS)
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(WS2_LIBS)

AC_CONFIG_FILES([
	Makefile
	compat/Makefile
	compat/jansson/Makefile
	])
AC_OUTPUT
