#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <malloc.h>
#include <elf.h>
#include <string.h>

#include "hash.h"
#include "log.h"

static const char *hash_sects[] = {
	".rodata",
	".data",
	".test",
	NULL,
};

struct elf_file {
	union {
		Elf32_Ehdr elf32;
		Elf64_Ehdr elf64;
	} hdr;
	union {
		Elf32_Shdr *sht32;
		Elf64_Shdr *sht64;
	} sht;

	unsigned char ident[EI_NIDENT];
	char *sh_str;
	int fd;
};

static inline bool elf_is_32(struct elf_file *elf)
{
	return elf->ident[EI_CLASS] == ELFCLASS32;
}

static inline void *elf_hdr(struct elf_file *elf)
{
	return elf_is_32(elf) ? (void *)&elf->hdr.elf32:
	       			(void *)&elf->hdr.elf64;
}

static inline size_t elf_hdr_len(struct elf_file *elf)
{
	return elf_is_32(elf) ? sizeof(elf->hdr.elf32):
	       			sizeof(elf->hdr.elf64);
}

static inline uint32_t elf_hdr_stridx(struct elf_file *elf)
{
	if (elf_is_32(elf))
		return elf->hdr.elf32.e_shstrndx;

	return elf->hdr.elf64.e_shstrndx;
}

static inline off_t elf_hdr_shtoffs(struct elf_file *elf)
{
	if (elf_is_32(elf))
		return (off_t)elf->hdr.elf32.e_shoff;

	return (off_t)elf->hdr.elf64.e_shoff;
}


static inline uint32_t elf_sht_num(struct elf_file *elf)
{
	return elf_is_32(elf) ? elf->hdr.elf32.e_shnum:
	       			elf->hdr.elf64.e_shnum;
}

static inline uint32_t elf_sht_size(struct elf_file *elf)
{
	return elf_is_32(elf) ? elf->hdr.elf32.e_shentsize:
	       			elf->hdr.elf64.e_shentsize;
}

static inline void *elf_sht_tbl(struct elf_file *elf, uint32_t n)
{
	if (elf_is_32(elf))
		return &elf->sht.sht32[n];

	return &elf->sht.sht64[n];
}

static inline int elf_magic_check(struct elf_file *elf)
{
	return elf->ident[EI_MAG0] != ELFMAG0
		|| elf->ident[EI_MAG1] != ELFMAG1
		|| elf->ident[EI_MAG2] != ELFMAG2
		|| elf->ident[EI_MAG3] != ELFMAG3;
}

static struct elf_file *elf_file_alloc(void)
{
	struct elf_file *elf;

	elf = malloc(sizeof(struct elf_file));
	if (elf)
		elf->fd = -1;

	return elf;
}

static int elf_sht_read(struct elf_file *elf)
{
	size_t sht_len = elf_sht_num(elf) * elf_sht_size(elf);
	size_t len;

	if (lseek(elf->fd, elf_hdr_shtoffs(elf), SEEK_SET) != elf_hdr_shtoffs(elf))
		return error("Failed to move file to section headers table");

	elf->sht.sht32 = malloc(sht_len);
	if (!elf->sht.sht32)
		return error("Failed alloc section headers table\n");

	len = read(elf->fd, elf->sht.sht32, sht_len);
	if (len != sht_len)
		return error("Failed to read section headers table\n");

	return 0;
}

static size_t elf_sect_size(struct elf_file *elf, uint32_t n)
{
	if (elf_is_32(elf))
		return elf->sht.sht32[n].sh_size;
	else
		return elf->sht.sht64[n].sh_size;
}

static size_t elf_sect_offs(struct elf_file *elf, uint32_t n)
{
	if (elf_is_32(elf))
		return elf->sht.sht32[n].sh_offset;
	else
		return elf->sht.sht64[n].sh_offset;
}

static uint8_t *elf_sect_read(struct elf_file *elf, uint32_t n)
{
	off_t offset = elf_sect_offs(elf, n);
	size_t size = elf_sect_size(elf, n);
	uint8_t *sect;

	sect = malloc(size);
	if (!sect) {
		error("Failed alloc strings section %u size %u\n", n, size);
		return NULL;
	}

	if (lseek(elf->fd, offset, SEEK_SET) != offset) {
		error("Failed to move file to strings table\n");
		return NULL;
	}

	if (read(elf->fd, sect, size) != size) {
		error("Failed to read strings table\n");
		return NULL;
	}

	return sect;
}

static char *elf_sect_name(struct elf_file *elf, uint32_t n)
{
	off_t offset;

	if (elf_is_32(elf))
		offset = elf->sht.sht32[n].sh_name;
	else
		offset = elf->sht.sht64[n].sh_name;

	return elf->sh_str + offset;
}

static int elf_strings_read(struct elf_file *elf)
{
	elf->sh_str = (char *)elf_sect_read(elf, elf_hdr_stridx(elf));
	if (!elf->sh_str)
		return error("Failed to read strings section\n");

	return 0;
}

static void elf_file_free(struct elf_file *elf)
{
	free(elf->sht.sht32);
	free(elf->sh_str);
	free(elf);
}

static int elf_file_open(struct elf_file *elf, const char *file)
{
       	elf->fd = open(file, O_RDONLY | O_SYNC);
	if(elf->fd < 0)
		return error("Failed open %s\n", file);

	return 0;
}

static void elf_file_close(struct elf_file *elf)
{
	if (elf->fd != -1)
		close(elf->fd);
}

static int elf_file_read(struct elf_file *elf)
{
	size_t len;

	if (lseek(elf->fd, 0, SEEK_SET) != 0)
		return error("Failed move file pos at 0\n");

	len = read(elf->fd, &elf->ident, sizeof(elf->ident));
	if (len != sizeof(elf->ident))
		return error("Failed to read ELF ident field\n");

	if (lseek(elf->fd, 0, SEEK_SET) != 0)
		return error("Failed move file pos at 0\n");

	len = read(elf->fd, elf_hdr(elf), elf_hdr_len(elf));
	if (len != elf_hdr_len(elf))
		return error("Failed to read ELF header\n");

	if (elf_magic_check(elf))
		return error("Invalid ELF file magic\n");

	if (elf_sht_read(elf))
		return -1;

	if (elf_strings_read(elf))
		return -1;

	return 0;
}

int elf_file_hash(const char *path, struct hash_alg *alg, uint8_t *hash)
{
	struct elf_file *elf;
	int err = -1;
	uint32_t i;

	if (hash_alg_init(alg))
		return error("Failed init hash alg\n");

	elf = elf_file_alloc();
	if (!elf)
		return error("Failed allocate elf_file struct\n");

	err = elf_file_open(elf, path);
	if (err)
		goto out;

	err = elf_file_read(elf);
	if (err)
		goto out;

	for (i = 0; i < elf_sht_num(elf); i++) {
		const char **sname;

		for (sname = hash_sects; *sname != NULL; sname++) {
			uint8_t *sect;

			if (strcmp(*sname, elf_sect_name(elf, i)) != 0)
				continue;

			sect = elf_sect_read(elf, i);
			if (!sect) {
				error("Failed to read section %s\n", *sname);
				free(sect);
				err = -1;
				goto out;
			}

			err = hash_alg_update(alg, sect, elf_sect_size(elf, i));
			if (err) {
				error("Failed to update hash for section %s\n", *sname);
				free(sect);
				goto out;
			}

			free(sect);
		}
	}

	err = hash_alg_finish(alg, hash);
	if (err) {
		error("Failed to finish hash\n");
	}
out:
	elf_file_close(elf);
	elf_file_free(elf);
	return err;
}
