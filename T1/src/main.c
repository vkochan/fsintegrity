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

enum integrity_check_t {
	INTEGRITY_CHECK_NONE,
	INTEGRITY_CHECK_RAW,
	INTEGRITY_CHECK_ELF,
};

static enum integrity_check_t enhash_type = INTEGRITY_CHECK_RAW;
static char *enhash_file;
static char *enhash_alg;
static char *conf_file;
static char *log_file;
static char *pid_file;

static const char *pid_file_created;

char hstr[MAX_HASH_SIZE * 2 + 1] = {0};
uint8_t hash[MAX_HASH_SIZE];

struct conf_entry {
	enum integrity_check_t check;
	struct list_head list;
	struct hash_alg *alg;
	bool is_corrupted;
	uint8_t *hash;
	char *file;
};

enum conf_token_t {
	CONF_TOK_ALG,
	CONF_TOK_HASH,
	CONF_TOK_FILE,
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

			state = CONF_TOK_FILE;
			break;

		case CONF_TOK_FILE:
			if (strncmp("elf", tok, 3) == 0) {
				conf->check = INTEGRITY_CHECK_ELF;
			} else if (strncmp("raw", tok, 3) == 0) {
				conf->check = INTEGRITY_CHECK_RAW;
			} else {
				error("Expecting 'elf' or 'raw' keyword\n");
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
	int err = -1;
	char buf[64];
	int slen;
	int fd;

	if (stat(file, &st) == 0)
		return -1;

	fd = open(file, O_RDWR|O_CREAT, 0640);
	if (fd < 0)
		return -1;

	sprintf(buf, "%d\n", getpid());
	slen = strlen(buf);

	if (write(fd, buf, slen) != slen) {
		error("Failed to wrote pid into file\n");
		err = -1;
		goto out;
	}

	pid_file_created = file;
	err = 0;
out:
	close(fd);
	return err;
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
	printf("   -t, --type     NAME       check type: 'elf' or 'raw' (default)\n");
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
	{ "type", required_argument, 0, 't' },
	{ NULL, 0, 0, 0}
};

static int parse_args(int argc, char **argv)
{
	int opt, idx = 0;

	while ((opt = getopt_long(argc, argv, "c:l:t:p:e:t:dh", long_opts, &idx)) != -1) {
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
		case 't':
			if (strncmp("elf", optarg, 3) == 0) {
				enhash_type = INTEGRITY_CHECK_ELF;
			} else if (strncmp("raw", optarg, 3) == 0) {
				enhash_type = INTEGRITY_CHECK_RAW;
			} else {
				fprintf(stderr, "Invalid enhash type: %s\n", optarg);
				help();
				exit(1);
			}
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

static int raw_file_hash(const char *file, struct hash_alg *alg, uint8_t *hash)
{
	uint8_t buf[4096];
	int err = -1;
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp)
		return error("Failed to open raw file %s\n", file);

	err = hash_alg_init(alg);
	if (err)
		goto out;

	while (!feof(fp)) {
		ssize_t len;

		len = fread(buf, 1, sizeof(buf), fp);
		if (len <= 0)
			break;

		err = hash_alg_update(alg, buf, len);
		if (err)
			goto out;
	}

	err = hash_alg_finish(alg, hash);
out:
	fclose(fp);
	return err;
}

static int integrity_calc(const char *file, enum integrity_check_t check,
			  struct hash_alg *alg, uint8_t *hash)
{
	switch (check) {
	case INTEGRITY_CHECK_RAW:
		return raw_file_hash(file, alg, hash);

	case INTEGRITY_CHECK_ELF:
		return elf_file_hash(file, alg, hash);

	case INTEGRITY_CHECK_NONE:
	default:
		assert(false);
	}
}

static int integrity_check(struct conf_entry *conf)
{
	if (integrity_calc(conf->file, conf->check, conf->alg, hash))
		return error("Failed enhash file %s\n", conf->file);

	if (memcmp(hash, conf->hash, hash_alg_size(conf->alg)) != 0) {
		if (!conf->is_corrupted) {
			pid_t pid;

			bin2hex(hstr, hash, hash_alg_size(conf->alg));

			if (conf->check == INTEGRITY_CHECK_ELF) {
				pid = pid_by_path_get(conf->file);
				alert("ELF is corrupted pid(%u): elf:%s:%s\n", pid, conf->file, hstr);
			} else if (conf->check == INTEGRITY_CHECK_RAW) {
				alert("File is corrupted: raw:%s:%s\n", conf->file, hstr);
			} else {
				assert(false);
			}

			conf->is_corrupted = true;
		}
	} else if (conf->is_corrupted) {
		alert("File is fixed: %s\n", conf->file);
		conf->is_corrupted = false;
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

		if (integrity_calc(enhash_file, enhash_type, alg, hash)) {
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
			if (integrity_check(conf)) {
				error("Integrity check failed\n");
				goto out;
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
