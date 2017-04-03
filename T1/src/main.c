#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>

#include "log.h"
#include "list.h"
#include "hash.h"
#include "util.h"
#include "config.h"
#include "elf_file.h"

#define DEFAULT_PID_FILE	"/var/run/"PACKAGE".pid"
#define DEFAULT_HASH_ALG	"sha1"
#define CONF_FILE		"psmon.conf"
#define APP_NAME		PACKAGE

static bool is_running = false;
static bool is_daemon = false;

static char *enhash_file;
static char *enhash_alg;
static char *conf_file;
static char *log_file;
static char *pid_file;

static const char *pid_file_created;

char hstr[MAX_HASH_SIZE * 2 + 1] = {0};
uint8_t hash[MAX_HASH_SIZE];

struct conf_entry {
	struct list_head list;
	struct hash_alg *alg;
	bool is_corrupted;
	uint8_t *hash;
	char *file;
};

enum conf_token_t {
	CONF_TOK_ALG,
	CONF_TOK_HASH,
	CONF_TOK_ELF,
	CONF_TOK_PATH,
	CONF_TOK_END,
};

struct list_head conf_list;

static struct conf_entry *conf_entry_alloc()
{
	return calloc(1, sizeof(struct conf_entry));
}

static void conf_entry_free(struct conf_entry *conf)
{
	if (!conf)
		return;

	hash_alg_free(conf->alg);
	free(conf->file);
	free(conf->hash);
}

static struct conf_entry *conf_entry_parse(char *line)
{
	enum conf_token_t state = CONF_TOK_ALG;
	struct conf_entry *conf;
	uint32_t hstr_len;;
	char *s = line;
	struct stat st;
	uint32_t hsize;
	char *crnl;
	char *tok;

	conf = conf_entry_alloc();
	if (!conf) {
		error("Failed to allocate conf entry\n");
		goto err;
	}

	while (CONF_TOK_END != state && (tok = strtok(s, ":")) != NULL) {
		switch (state) {
		case CONF_TOK_ALG:
			conf->alg = hash_alg_create(tok);
			if (!conf->alg) {
				error("Failed to create hash alg: %s\n", tok);
				goto err;
			}

			hsize = hash_alg_size(conf->alg);
			state = CONF_TOK_HASH;
			break;

		case CONF_TOK_HASH:
			hstr_len = strlen(tok);
			if (hstr_len != hsize * 2) {
				error("Hash size must be %u\n", hsize * 2);
				goto err;
			}

			conf->hash = malloc(hsize);
			if (!conf->hash) {
				error("Failed allocate hash buffer\n");
				goto err;
			}

			if (hex2bin(conf->hash, tok, hsize)) {
				error("Failed to convert hex to bytes\n");
				goto err;
			}

			state = CONF_TOK_ELF;
			break;

		case CONF_TOK_ELF:
			if (strncmp("elf", tok, 3) != 0) {
				error("Expecting ':elf:' keyword\n");
				goto err;
			}

			state = CONF_TOK_PATH;
			break;

		case CONF_TOK_PATH:
			conf->file = strdup(tok);
			if (!conf->file) {
				error("Failed to allocate file path\n");
				goto err;
			}

			crnl = strpbrk(conf->file, "\r\n");
			if (crnl)
				*crnl = '\0';

			if (stat(conf->file, &st)) {
				error("File %s does not exist\n", conf->file);
				goto err;
			}

			state = CONF_TOK_END;
			break;

		case CONF_TOK_END:
		default:
			assert(false);
		}

		s = NULL;
	}

	return conf;
err:
	conf_entry_free(conf);
	return NULL;
}

static int config_read(void)
{
	char *path = conf_file ? conf_file: CONF_DIR"/"CONF_FILE;
	uint32_t count = 0;
	char line[1024];
	int err = -1;
	FILE *f;

	f = fopen(path, "r");
	if (!f) {
		warn("Failed open conf file: %s\n", path);
		return 0;
	}

	while (fgets(line, sizeof(line), f) != NULL && ++count) {
		struct conf_entry *en;
		char *s = strdup(line);

		en = conf_entry_parse(s);
		if (!en) {
			error("Failed parse config entry, line %u: %s\n", count, line);
			free(s);
			err = -1;
			goto out;
		}
		free(s);

		list_add_tail(&en->list, &conf_list);
	}

	err = 0;
out:
	fclose(f);
	return err;
}

static void config_free(void)
{
	struct conf_entry *conf, *tmp;

	list_for_each_entry_safe(conf, tmp, &conf_list, list) {
		list_del(&conf->list);
		conf_entry_free(conf);
	}
}

static int pid_file_write(const char *file, pid_t pid)
{
	struct stat st;
	char buf[64];
	int fd;

	if (stat(file, &st) == 0)
		return -1;

	fd = open(file, O_RDWR|O_CREAT, 0640);
	if (fd < 0)
		return -1;

	sprintf(buf, "%d\n", getpid());
	write(fd, buf, strlen(buf));

	pid_file_created = file;
	close(fd);
	return 0;
}

static void handle_signal(int sig)
{
	switch (sig) {
	case SIGINT:
		is_running = false;
		break;

	/* Reload the configuration */
	case SIGHUP:
		config_free();

		if (config_read())
			error("Failed to read config file\n");

		info("Config is reloaded\n");
		break;
	}
}

static int signal_init(void)
{
	signal(SIGINT, handle_signal);
	signal(SIGHUP, handle_signal);

	return 0;
}

static int daemonize(void)
{
	pid_t pid, sid;

	pid = fork();
	if (pid < 0)
		exit(EXIT_FAILURE);
	if (pid > 0)
		exit(EXIT_SUCCESS);


	sid = setsid();
	if (sid < 0)
		exit(EXIT_FAILURE);

	signal(SIGCHLD, SIG_IGN);

	pid = fork();
	if (pid < 0)
		exit(EXIT_FAILURE);
	if (pid > 0)
		exit(EXIT_SUCCESS);

	umask(0);

	if ((chdir("/")) < 0)
		exit(EXIT_FAILURE);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	if (pid_file_write(pid_file ?: DEFAULT_PID_FILE, getpid()))
		return -1;

	return 0;
}

void help(void)
{
	printf("\n Usage: %s [OPTIONS]\n\n", APP_NAME);
	printf("  Options:\n");
	printf("   -h --help                 print help\n");
	printf("   -l --log       FILE       write logs to the file\n");
	printf("   -c --conf      FILE       load config from the file\n");
	printf("   -p --pid       FILE       pid file\n");
	printf("   -d --daemon               run in background\n");
	printf("   -e --enhash    FILE       enhash file only\n");
	printf("   -a, --alg      NAME       hash alg: sha1(default), md5\n");
	printf("\n");
}

static const struct option long_opts[] = {
	{ "help", no_argument, 0, 'h' },
	{ "log", required_argument, 0, 'l' },
	{ "conf", required_argument, 0, 'c' },
	{ "pid", required_argument, 0, 'p' },
	{ "daemon", no_argument, 0, 'd' },
	{ "enhash", required_argument, 0, 'e' },
	{ "alg", required_argument, 0, 'a' },
	{ NULL, 0, 0, 0}
};

static int parse_args(int argc, char **argv)
{
	int opt, idx = 0;

	while ((opt = getopt_long(argc, argv, "c:l:t:p:e:dh", long_opts, &idx)) != -1) {
		switch (opt) {
		case 'c':
			conf_file = strdup(optarg);
			break;
		case 'l':
			log_file = strdup(optarg);
			break;
		case 'p':
			pid_file = strdup(optarg);
			break;
		case 'd':
			is_daemon = true;
			break;
		case 'e':
			enhash_file = strdup(optarg);
			break;
		case 'a':
			enhash_alg = strdup(optarg);
			break;
		case 'h':
		case '?':
			help();
			exit(0);
		default:
			fprintf(stderr, "Invalid option: %c\n", opt);
			help();
			exit(1);
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	enum log_t log = LOGGING_CONSOLE;
	char *log_name = NULL;
	int rc = -1;

	INIT_LIST_HEAD(&conf_list);

	if (parse_args(argc, argv)) {
		fprintf(stderr, "Failed to parse args\n");
		goto out;
	}

	if (enhash_file) {
		struct hash_alg *alg = hash_alg_create(enhash_alg ? enhash_alg
						: DEFAULT_HASH_ALG);

		if (!alg) {
			error("Failed create alg to enhash file\n");
			goto out;
		}

		if (elf_file_hash(enhash_file, alg, hash)) {
			error("Failed enhash file %s\n");
			goto out;
		}

		bin2hex(hstr, hash, hash_alg_size(alg));
		printf("%s\n", hstr);

		rc = 0;
		goto out;
	}

	if (is_daemon) {
		if (daemonize())
			return -1;

		log = LOGGING_SYSLOG;
		log_name = APP_NAME;
	}

	if (log_file) {
		log = LOGGING_FILE;
		log_name = log_file;	
	}

	if (log_init(log, log_name))
		goto out;

	if (signal_init())
		goto out;

	if (config_read()) {
		error("Failed to read config file\n");
		goto out;
	}

	info("Started %s\n", APP_NAME);

	is_running = true;
	while (is_running) {
		struct conf_entry *conf;

		list_for_each_entry(conf, &conf_list, list) {
			if (elf_file_hash(conf->file, conf->alg, hash)) {
				error("Failed enhash file %s\n", conf->file);
				continue;
			}

			if (memcmp(hash, conf->hash, hash_alg_size(conf->alg)) != 0) {
				if (!conf->is_corrupted) {
					bin2hex(hstr, hash, hash_alg_size(conf->alg));
					alert("File is corrupted: %s:%s\n", conf->file, hstr);
					conf->is_corrupted = true;
				}
			} else if (conf->is_corrupted) {
				alert("File is fixed: %s\n", conf->file);
				conf->is_corrupted = false;
			}
		}

		sleep(1);
	}
	info("Exiting ...\n", APP_NAME);

	rc = 0;
out:
	if (is_daemon && pid_file_created)
		unlink(pid_file_created);

	free(enhash_file);
	free(enhash_alg);
	free(conf_file);
	free(pid_file);
	free(log_file);

	config_free();
	log_uninit();

	return rc;
}
