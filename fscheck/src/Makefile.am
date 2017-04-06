AM_CFLAGS = -Wall -std=gnu99 -O2

bin_PROGRAMS = fsintegr

fsintegr_LDADD = $(OPENSSL_LIBS)
fsintegr_CFLAGS = $(AM_CFLAGS) -DCONF_DIR="\"$(sysconfdir)/psmon.conf\""
fsintegr_SOURCES = main.c log.c hash.c elf_file.c util.c
