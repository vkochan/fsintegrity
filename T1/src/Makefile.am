AM_CFLAGS = -Wall -std=gnu99 -O2

bin_PROGRAMS = pshasher

pshasher_LDADD = $(OPENSSL_LIBS)
pshasher_CFLAGS = $(AM_CFLAGS) -DCONF_DIR="\"$(sysconfdir)/psmon.conf\""
pshasher_SOURCES = main.c log.c hash.c elf_file.c util.c
