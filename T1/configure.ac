#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([pshasher], [0.0.1], [vadim4j@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

: ${CFLAGS=""}

AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

# Checks for programs.

# Checks for libraries.
PKG_CHECK_MODULES([OpenSSL], [openssl])

# Checks for header files.
AC_CHECK_HEADERS([openssl/sha.h openssl/md5.h elf.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

test "$sysconfdir" = '${prefix}/etc' && sysconfdir=/etc

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
