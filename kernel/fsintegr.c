#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/security.h>
#include <linux/seq_file.h>

#include <crypto/sha.h>
#include <crypto/md5.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>

static struct task_struct *fsintegr_task;

static struct dentry *fs_config;
static struct dentry *fs_events;
static struct dentry *fs_dir;

enum config_token_t {
	HENTRY_TOK_CMD,
	HENTRY_TOK_ALG,
	HENTRY_TOK_HASH,
	HENTRY_TOK_PATH,
	HENTRY_TOK_FNAME,
	HENTRY_TOK_END,
};

enum config_cmd_t {
	HENTRY_CMD_NONE,
	HENTRY_CMD_ADD,
	HENTRY_CMD_DEL,
};

#define HASH_SIZE_MAX	SHA1_DIGEST_SIZE

enum fsintegr_event_id_t {
	FSINTEGR_EVT_VIOLATED,
	FSINTEGR_EVT_FIXED,
};

struct fsintegr_event {
	enum fsintegr_event_id_t id;
	struct list_head list;
	struct rcu_head rcu;
	char *path;
};

struct fsintegr_config {
	struct list_head list;
	struct rcu_head rcu;
	bool is_violated;
	char *path;
	u8 *hash;
	int alg;
};

static LIST_HEAD(entries);
static LIST_HEAD(events);

DEFINE_MUTEX(config_mtx);
DEFINE_MUTEX(evt_mtx);

static void *fs_config_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct fsintegr_config *cf;
	loff_t n = *pos;

	rcu_read_lock();
	list_for_each_entry_rcu(cf, &entries, list) {
		if (!n--) {
			rcu_read_unlock();
			return cf;
		}
	}

	return NULL;
}

static void *fs_config_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct fsintegr_config *cf = v;

	cf = list_next_or_null_rcu(&entries, &cf->list,
				    struct fsintegr_config, list);
	(*pos)++;

	return cf;
}

static void fs_config_seq_stop(struct seq_file *m, void *v)
{
	rcu_read_unlock();
}

static int fs_config_seq_show(struct seq_file *seq, void *v)
{
	struct fsintegr_config *cf = v;
	char hash[HASH_SIZE_MAX * 2 + 1];
	
	if (!cf)
		return -1;

	bin2hex(hash, cf->hash, hash_digest_size[cf->alg]);
	hash[hash_digest_size[cf->alg] * 2] = '\0';

	seq_printf(seq, "%s:", hash_algo_name[cf->alg]);
	seq_printf(seq, "%s:", hash);
	seq_printf(seq, "file:%s\n", cf->path);

	return 0;
}
 
static const struct seq_operations fs_config_seq_ops = {
	.start = fs_config_seq_start,
	.next = fs_config_seq_next,
	.stop = fs_config_seq_stop,
	.show = fs_config_seq_show,
};

static int fs_config_open(struct inode *inode, struct file *file)
{
	if (file->f_flags & O_WRONLY)
		return 0;
	if ((file->f_flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;

	return seq_open(file, &fs_config_seq_ops);
}

static void *fs_events_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct fsintegr_event *ev, *tmp;
	loff_t n = *pos;

	/* We need a lock here because events will be removed while read-ing */
	mutex_lock(&evt_mtx);

	list_for_each_entry_safe(ev, tmp, &events, list) {
		if (!n--)
			return ev;
	}

	return NULL;
}

static void event_free_rcu_cb(struct rcu_head *rcu)
{
	struct fsintegr_event *ev = container_of(rcu, struct fsintegr_event, rcu);

	if (ev->path)
		kfree(ev->path);

	kfree(ev);
}

static void *fs_events_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct fsintegr_event *ev = v;
	struct fsintegr_event *next;

	next = list_next_or_null_rcu(&events, &ev->list,
				      struct fsintegr_event, list);
	(*pos)++;

	list_del_rcu(&ev->list);
	call_rcu(&ev->rcu, event_free_rcu_cb);

	return next;
}

static void fs_events_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&evt_mtx);
}

static int fs_events_seq_show(struct seq_file *seq, void *v)
{
	struct fsintegr_event *ev = v;
	char *name;
	
	if (!ev)
		return -1;

	switch (ev->id) {
	case FSINTEGR_EVT_VIOLATED:
		name = "violated";
		break;

	case FSINTEGR_EVT_FIXED:
		name = "fixed";
		break;

	default:
		BUG();
	}

	seq_printf(seq, "%s:file:%s\n", name, ev->path);
	return 0;
}
 
static const struct seq_operations fs_events_seq_ops = {
	.start = fs_events_seq_start,
	.next = fs_events_seq_next,
	.stop = fs_events_seq_stop,
	.show = fs_events_seq_show,
};

static int fs_events_open(struct inode *inode, struct file *file)
{
	if ((file->f_flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;

	return seq_open(file, &fs_events_seq_ops);
}

static int config_by_path_add(int alg, char *path, u8 *hash, size_t hlen)
{
	struct fsintegr_config *cf;

	if (alg == -1) {
		pr_err("undefined alg\n");
		return -EINVAL;
	}

	BUG_ON(hlen == 0);

	cf = kzalloc(sizeof(*cf), GFP_KERNEL);
	if (!cf)
		return -ENOMEM;

	cf->alg  = alg;
	cf->path = path;
	cf->hash = hash;

	INIT_LIST_HEAD(&cf->list);

	mutex_lock(&config_mtx);
	list_add_tail_rcu(&cf->list, &entries);
	mutex_unlock(&config_mtx);

	return 0;
}

static struct fsintegr_config *__config_by_path_get(const char *path)
{
	struct fsintegr_config *cf;

	list_for_each_entry_rcu(cf, &entries, list) {
		if (strcmp(path, cf->path) == 0) {
			return cf;
		}
	}

	return NULL;
}

static void config_free_rcu_cb(struct rcu_head *rcu)
{
	struct fsintegr_config *cf = container_of(rcu, struct fsintegr_config, rcu);

	if (cf->path)
		kfree(cf->path);
	if (cf->hash)
		kfree(cf->hash);

	kfree(cf);
}

static int config_by_path_del(char *path)
{
	struct fsintegr_config *cf;

	mutex_lock(&config_mtx);

	cf = __config_by_path_get(path);
	if (!cf) {
		mutex_unlock(&config_mtx);
		return -1;
	}
	list_del_rcu(&cf->list);

	mutex_unlock(&config_mtx);

	call_rcu(&cf->rcu, config_free_rcu_cb);
	return 0;
}

/* hash entry samples:
	add:sha1:<hash>:path:/<file path>
	add:md5:<hash>:path:/<file path>
	del:path:/<file path>
*/
static ssize_t fs_config_parse(char *str)
{
	enum config_token_t state = HENTRY_TOK_CMD;
	enum config_cmd_t cmd = HENTRY_CMD_NONE;
	ssize_t err = -EINVAL;
	char *path = NULL;
	char *hstr = NULL;
	u8 *hash = NULL;
	size_t hlen = 0;
	int alg = -1;
	char *crnl;
	char *ptr;

	while ((ptr = strsep(&str, ":")) && state != HENTRY_TOK_END) {
		switch (state) {
		case HENTRY_TOK_CMD:
			if (strncmp(ptr, "add", 3) == 0) {
				state = HENTRY_TOK_ALG;
				cmd = HENTRY_CMD_ADD;
			} else if (strncmp(ptr, "del", 3) == 0) {
				state = HENTRY_TOK_PATH;
				cmd = HENTRY_CMD_DEL;
			} else {
				pr_err("Invalid hash entry command\n");
				goto out;
			}
			break;

		case HENTRY_TOK_ALG:
			if (strncmp(ptr, "sha1", 4) == 0)
				alg = HASH_ALGO_SHA1;
			else if (strncmp(ptr, "md5", 3) == 0)
				alg = HASH_ALGO_MD5;

			hlen = hash_digest_size[alg];
			state = HENTRY_TOK_HASH;
			break;

		case HENTRY_TOK_HASH:
			err = -ENOMEM;
			hstr = kstrndup(ptr, (hlen * 2) + 1, GFP_KERNEL);
			if (!hstr)
				goto out;

			err = -EINVAL;
			if (strlen(hstr) != hlen * 2) {
				pr_err("Invalid hash length\b");
				goto out;
			}

			err = -ENOMEM;
			hash = kmalloc(hlen, GFP_KERNEL);
			if (!hash)
				goto out;

			err = -EINVAL;
			if (hex2bin(hash, hstr, hlen)) {
				pr_err("Invalid hash format\n");
				goto out;
			}

			state = HENTRY_TOK_PATH;
			break;

		case HENTRY_TOK_PATH:
			state = HENTRY_TOK_FNAME;
			break;

		case HENTRY_TOK_FNAME:
			err = -EINVAL;
			if (ptr[0] != '/') {
				pr_err("Invalid path - must start with '/'\n");
				goto out;
			}

			if (cmd == HENTRY_CMD_ADD) {
				err = -ENOMEM;
				path = kstrndup(ptr, NAME_MAX, GFP_KERNEL);
				if (!path)
					goto out;
			} else {
				path = ptr;
			}

			crnl = strpbrk(path, "\r\n");
			if (crnl)
				crnl[0] = '\0';

			state = HENTRY_TOK_END;
			break;

		case HENTRY_TOK_END:
		default:
			BUG();
		}
	}

	err = -EINVAL;
	if (!path) {
		pr_err("Invalid NULL path\n");
		goto out;
	}

	if (cmd == HENTRY_CMD_ADD)
		err = config_by_path_add(alg, path, hash, hlen);
	else if (cmd == HENTRY_CMD_DEL)
		err = config_by_path_del(path);
	else
		BUG();
out:
	if (err) {
		if (path)
			kfree(path);
		if (hash)
			kfree(hash);
	}

	if (hstr)
		kfree(hstr);

	return err;
}

static ssize_t fs_config_write(struct file *file, const char __user *buf,
			       size_t len, loff_t *ppos)
{
	ssize_t ret = -EINVAL;
	char *str;

	if (*ppos != 0)
		goto out;

	ret = -ENOMEM;
	str = kmalloc(len + 1, GFP_KERNEL);
	if (!str)
		goto out;

	*(str + len) = '\0';

	ret = -EFAULT;
	if (copy_from_user(str, buf, len))
		goto out_free;
	
	ret = fs_config_parse(str);
	if (ret)
		goto out;

	ret = len;
out_free:
	kfree(str);
out:
	return ret;
}

static const struct file_operations fs_config_ops = {
	.open = fs_config_open,
	.write = fs_config_write,
	.read = seq_read,
	.llseek = generic_file_llseek,
};

static const struct file_operations fs_events_ops = {
	.open = fs_events_open,
	.read = seq_read,
	.llseek = generic_file_llseek,
};

static inline void sleep(unsigned int sec)
{
	schedule_timeout_interruptible(sec * HZ);
}

static int file_read_buf(struct file *file, loff_t offs, char *buf,
			 unsigned long count)
{
	char __user *ubuf = (char __user *)buf;
	mm_segment_t old_fs;
	ssize_t ret;

	old_fs = get_fs();
	set_fs(get_ds());
	ret = __vfs_read(file, ubuf, count, &offs);
	set_fs(old_fs);

	return ret;
}

static int fsintegr_file_check(struct fsintegr_config *cf)
{
	const char *alg_name = hash_algo_name[cf->alg];
	struct crypto_shash *tfm = crypto_alloc_shash(alg_name, 0, 0);
	SHASH_DESC_ON_STACK(shash, tfm);
	loff_t i_size, offset = 0;
	struct file *file = NULL;
	u8 hash[HASH_SIZE_MAX];
	struct crypto_shash;
	unsigned int hsize;
	u8 *fbuf = NULL;
	int rc = 0;

	if (IS_ERR(tfm))
		return 0;

	shash->tfm = tfm;
	shash->flags = 0;

	if (crypto_shash_init(shash))
		goto out;

	hsize = crypto_shash_digestsize(tfm);

	fbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!fbuf)
		goto out;

	file = filp_open(cf->path, O_RDONLY, 0);
	if (IS_ERR(file))
		goto out;

	i_size = i_size_read(file_inode(file));
	if (i_size == 0)
		goto out;

	while (offset < i_size) {
		int len;

		len = file_read_buf(file, offset, fbuf, PAGE_SIZE);
		if (len <= 0)
			goto out;

		offset += len;

		if (crypto_shash_update(shash, fbuf, len))
			goto out;
	}

	if (crypto_shash_final(shash, hash))
		goto out;

	rc = memcmp(cf->hash, hash, hsize);
out:

	if (fbuf)
		kfree(fbuf);
	if (file)
		filp_close(file, 0);
	if (tfm)
		crypto_free_shash(tfm);

	return rc;
}

static void fsintegr_event_add(struct fsintegr_config *cf, enum fsintegr_event_id_t id)
{
	struct fsintegr_event *ev;

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if(!ev) {
		pr_err("failed to allocate event\n");
		return;
	}

	ev->id = id;
	ev->path = kstrndup(cf->path, NAME_MAX, GFP_KERNEL);
	if (!ev->path)
		goto err;

	INIT_LIST_HEAD(&ev->list);

	mutex_lock(&evt_mtx);
	list_add_tail_rcu(&ev->list, &events);
	mutex_unlock(&evt_mtx);

	return;
err:
	if (ev->path)
		kfree(ev->path);
	kfree(ev);
}

int fsintegr_thread(void *data) {
	while (!kthread_should_stop()) {
		struct fsintegr_config *cf;

		rcu_read_lock();
		list_for_each_entry_rcu(cf, &entries, list) {
			if (fsintegr_file_check(cf)) {
				if (!cf->is_violated)
					fsintegr_event_add(cf, FSINTEGR_EVT_VIOLATED);
				cf->is_violated = true;
			} else if (cf->is_violated) {
				fsintegr_event_add(cf, FSINTEGR_EVT_FIXED);
				cf->is_violated = false;
			}
		}
		rcu_read_unlock();

		sleep(2);
	}

	return 0;
}

int fsintegr_init(void)
{
	pr_info("Initialize Filesystem Integrity module\n");

	fs_dir = securityfs_create_dir("fsintegr", NULL);
	if (IS_ERR(fs_dir)) {
		pr_err("failed to create dir: %s\n", "fsintegr");
		return -1;
	}

	fs_events = securityfs_create_file("events", S_IRUSR | S_IRGRP,
				           fs_dir, NULL, &fs_events_ops);
	if (IS_ERR(fs_events))
		goto err;

	fs_config = securityfs_create_file("config", S_IRUSR | S_IRGRP,
				          fs_dir, NULL, &fs_config_ops);
	if (IS_ERR(fs_config))
		goto err;

	fsintegr_task = kthread_run(fsintegr_thread, NULL, "kfsintegr");

	return 0;
err:
	securityfs_remove(fs_events);
	securityfs_remove(fs_config);
	securityfs_remove(fs_dir);

	return -1;
}
 
void fsintegr_exit(void)
{
	kthread_stop(fsintegr_task);

	securityfs_remove(fs_events);
	securityfs_remove(fs_config);
	securityfs_remove(fs_dir);
}

module_init(fsintegr_init);
module_exit(fsintegr_exit);

MODULE_DESCRIPTION("File System Integrity");
MODULE_AUTHOR("Vadim Kochan");
MODULE_LICENSE("GPL");
