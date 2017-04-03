#ifndef __ELF_FILE_H__
#define __ELF_FILE_H__

#include "hash.h"

int elf_file_hash(const char *path, struct hash_alg *alg, uint8_t *hash);

#endif /* __ELF_FILE_H__ */
