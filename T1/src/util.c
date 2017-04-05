/* Borrowed from the Linux kernel */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <dirent.h>

#include "log.h"

/* All the hex conversions were borrowed from the Linux kernel */
const char hex_asc[] = "0123456789abcdef";

#define hex_asc_lo(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)   hex_asc[((x) & 0xf0) >> 4]

static inline char *hex_byte_pack(char *buf, uint8_t byte)
{
        *buf++ = hex_asc_hi(byte);
        *buf++ = hex_asc_lo(byte);
        return buf;
}

int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

int hex2bin(uint8_t *dst, const char *src, size_t count)
{
	while (count--) {
		int hi = hex_to_bin(*src++);
		int lo = hex_to_bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -1;

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}

char *bin2hex(char *dst, const void *src, size_t count)
{
	const unsigned char *_src = src;

	while (count--)
		dst = hex_byte_pack(dst, *_src++);
	return dst;
}

pid_t pid_by_path_get(const char *path)
{
	struct dirent *dent;
	DIR *dir;

	dir = opendir("/proc");
	if (!dir) {
		error("Failed to open /proc\n");
		return 0;
	}

	while ((dent = readdir(dir))) {
		char cmdl[1024] = {0};
		FILE *file;
		char *eol;

		if (snprintf(cmdl, sizeof(cmdl), "/proc/%s/cmdline", dent->d_name) < 0)
			continue;

		file = fopen(cmdl, "r");
		if (!file)
			continue;

		if (fgets(cmdl, sizeof(cmdl), file) == NULL)
			continue;

		eol = strpbrk(cmdl, " \r\n");
		if (eol)
			eol[0] = '\0';

		if (strcmp(path, cmdl) == 0)
			return atoi(dent->d_name);
	}

	return 0;
}
