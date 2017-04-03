#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include "log.h"

static FILE *flog;

int log_init(enum log_t log, char *name)
{
	switch (log) {
	case LOGGING_CONSOLE:
		flog = stdout;
		return 0;

	case LOGGING_SYSLOG:
		openlog(name, LOG_CONS | LOG_NDELAY, LOG_DAEMON);
		return 0;
	
	case LOGGING_FILE:
		flog = fopen(name, "w+");
		if (!flog)
			return -1;
		return 0;
	}

	return 0;
}

void log_uninit(void)
{
	if (flog && flog != stdout)
		fclose(flog);
}

static char *get_level_str(int level)
{
    switch (level)
    {
        case LOG_ERR:
            return "<error> ";
	case LOG_ALERT:
	    return "<alert> ";
        case LOG_INFO:
            return "<info> ";
        case LOG_WARNING:
            return "<warning> ";
    }

    return "";
}

int log_printf(int level, const char *fmt, ...)
{
    va_list args;

    if (flog)
    {
        fprintf(flog, "%s", get_level_str(level));

        va_start(args, fmt);
        vfprintf(flog, fmt, args);
        va_end(args);
	fflush(flog);
    }
    else
    {
        va_start(args, fmt);
        vsyslog(level, fmt, args);
        va_end(args);
    }

    return level == LOG_ERR ? -1 : 0;
}
