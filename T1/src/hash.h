#ifndef __HASH_H__
#define __HASH_H__

#include <openssl/sha.h>
#include <openssl/md5.h>

#define MAX_HASH_SIZE SHA_DIGEST_LENGTH

enum hash_alg_t {
	HASH_ALG_SHA1,
	HASH_ALG_MD5,
	HASH_ALG_MAX,
};

const char *hash_name[HASH_ALG_MAX];
const int hash_size[HASH_ALG_MAX];

struct hash_alg;

struct hash_alg_ops {
	int (*hash_init)(struct hash_alg *alg);
	int (*hash_update)(struct hash_alg *alg, const void *data, size_t len);
	int (*hash_finish)(struct hash_alg *alg, unsigned char *digest);
};

struct hash_alg {
	const struct hash_alg_ops *ops;
	enum hash_alg_t alg_id;

	union {
		SHA_CTX sha1;
		MD5_CTX md5;
	} ctx;
};

struct hash_alg *hash_alg_create(const char *name);
void hash_alg_free(struct hash_alg *alg);
int hash_alg_init(struct hash_alg *alg);
size_t hash_alg_size(struct hash_alg *alg);
int hash_alg_update(struct hash_alg *alg, const void *data, size_t len);
int hash_alg_finish(struct hash_alg *alg, unsigned char *digest);

#endif /* __HASH_H__ */
