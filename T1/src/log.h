#ifndef __LOG_H__
#define __LOG_H__

#include <syslog.h>

enum log_t {
	LOGGING_CONSOLE,
	LOGGING_SYSLOG,
	LOGGING_FILE,
};

int log_init(enum log_t log, char *name);
void log_uninit(void);

int log_printf(int level, const char *fmt, ...);

#define info( ...) log_printf(LOG_INFO, __VA_ARGS__)
#define error( ...) log_printf(LOG_INFO, __VA_ARGS__)
#define warn( ...) log_printf(LOG_WARNING, __VA_ARGS__)
#define alert( ...) log_printf(LOG_ALERT, __VA_ARGS__)

#endif /* __LOG_H__ */
