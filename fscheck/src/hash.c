#include <assert.h>
#include <malloc.h>
#include <string.h>
#include <inttypes.h>

#include "log.h"
#include "hash.h"

const char *hash_name[] = {
	[HASH_ALG_SHA1]	= "sha1",
	[HASH_ALG_MD5]	= "md5",
};

const int hash_size[] = {
	[HASH_ALG_SHA1]	= SHA_DIGEST_LENGTH,
	[HASH_ALG_MD5]	= MD5_DIGEST_LENGTH,
};

static int sha1_init(struct hash_alg *alg)
{
	return SHA1_Init(&alg->ctx.sha1) == 0;
}

static int sha1_update(struct hash_alg *alg, const void *data, size_t len)
{
	return SHA1_Update(&alg->ctx.sha1, data, len) == 0;
}

static int sha1_finish(struct hash_alg *alg, unsigned char *digest)
{
	return SHA1_Final(digest, &alg->ctx.sha1) == 0;
}

static const struct hash_alg_ops sha1_ops = {
	.hash_init    = sha1_init,
	.hash_update = sha1_update,
	.hash_finish = sha1_finish,
};

static int md5_init(struct hash_alg *alg)
{
	return MD5_Init(&alg->ctx.md5) == 0;
}

static int md5_update(struct hash_alg *alg, const void *data, size_t len)
{
	return MD5_Update(&alg->ctx.md5, data, len) == 0;
}

static int md5_finish(struct hash_alg *alg, unsigned char *digest)
{
	return MD5_Final(digest, &alg->ctx.md5) == 0;
}

static const struct hash_alg_ops md5_ops = {
	.hash_init    = md5_init,
	.hash_update = md5_update,
	.hash_finish = md5_finish,
};

static const struct hash_alg_ops *hash_ops[] = {
	[HASH_ALG_SHA1] = &sha1_ops,
	[HASH_ALG_MD5] = &md5_ops,
};

struct hash_alg *hash_alg_create(const char *name)
{
	enum hash_alg_t alg_id;
	struct hash_alg *alg;
	uint32_t i;

	alg = calloc(1, sizeof(struct hash_alg));
	if (!alg) {
		error("Failed to allocate hash alg\n");
		return NULL;
	}

	for (i = 0; i < HASH_ALG_MAX; i++) {
		if (strcmp(hash_name[i], name) == 0) {
			alg_id = i;
			break;
		}
	}
	if (i == HASH_ALG_MAX) {
		error("Invalid hash alg: %s\n", name);
		return NULL;
	}

	alg->ops = hash_ops[alg_id];
	alg->alg_id = alg_id;
	return alg;
}

void hash_alg_free(struct hash_alg *alg)
{
	if (alg)
		free(alg);
}

int hash_alg_init(struct hash_alg *alg)
{
	return alg->ops->hash_init(alg);
}

size_t hash_alg_size(struct hash_alg *alg)
{
	assert(alg->alg_id < HASH_ALG_MAX);

	return hash_size[alg->alg_id];
}

int hash_alg_update(struct hash_alg *alg, const void *data, size_t len)
{
	return alg->ops->hash_update(alg, data, len);
}

int hash_alg_finish(struct hash_alg *alg, unsigned char *digest)
{
	return alg->ops->hash_finish(alg, digest);
}
