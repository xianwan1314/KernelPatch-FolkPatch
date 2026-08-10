/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Block vendor vr.ko before the original init_module/finit_module syscall runs.
 */

#include <baselib.h>
#include <hook.h>
#include <ksyms.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <log.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

#define VR_MAX_SECTIONS 512
#define VR_MAX_SHSTRTAB (64 * 1024)
#define VR_MAX_MODINFO (16 * 1024)
#define VR_LOG_TAG "init_module_filter"

#ifndef SEEK_SET
#define SEEK_SET 0
#endif

#ifndef SEEK_END
#define SEEK_END 2
#endif

struct vr_module_reader {
    const char __user *umod;
    unsigned long umod_len;
    struct file *file;
    loff_t file_size;
};

static int vr_reader_read(struct vr_module_reader *reader, loff_t offset, void *buf, size_t len)
{
    loff_t total = reader->umod ? (loff_t)reader->umod_len : reader->file_size;

    if (len == 0) {
        logkw(VR_LOG_TAG ": read zero length\n");
        return -1;
    }
    if (offset < 0 || (loff_t)len > total || offset > total - (loff_t)len) {
        logkw(VR_LOG_TAG ": read out of range offset=%lld len=%zu total=%lld\n", offset, len, total);
        return -1;
    }

    if (reader->umod) {
        void *tmp = memdup_user(reader->umod + offset, len);
        if (IS_ERR_OR_NULL(tmp)) {
            logkw(VR_LOG_TAG ": memdup_user failed offset=%lld len=%zu rc=%ld\n", offset, len, PTR_ERR(tmp));
            return -1;
        }
        lib_memcpy(buf, tmp, len);
        kfree(tmp);
        return 0;
    }

    {
        loff_t pos = offset;
        ssize_t n = kernel_read(reader->file, buf, len, &pos);
        if (n < 0 || (size_t)n != len) {
            logkw(VR_LOG_TAG ": kernel_read failed offset=%lld len=%zu rc=%ld\n", offset, len, n);
            return -1;
        }
    }

    return 0;
}

static bool vr_module_is_target(struct vr_module_reader *reader)
{
    Elf64_Ehdr ehdr;
    Elf64_Shdr *shdrs = 0;
    char *shstrtab = 0;
    char *modinfo = 0;
    Elf64_Shdr *shstr_sh;
    Elf64_Shdr *modinfo_sh = 0;
    unsigned int shnum;
    unsigned int i;
    unsigned long shtab_bytes;
    bool is_vr = false;

    if (vr_reader_read(reader, 0, &ehdr, sizeof(ehdr))) {
        logkw(VR_LOG_TAG ": read elf header failed\n");
        return false;
    }

    if (lib_memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return false;
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        logki(VR_LOG_TAG ": skip non-ELF64 module class=%u\n", ehdr.e_ident[EI_CLASS]);
        return false;
    }
    if (ehdr.e_type != ET_REL) {
        logki(VR_LOG_TAG ": skip non-relocatable elf type=%u\n", ehdr.e_type);
        return false;
    }
    if (ehdr.e_shentsize != sizeof(Elf64_Shdr)) {
        logkw(VR_LOG_TAG ": invalid section header size=%u expected=%zu\n", ehdr.e_shentsize, sizeof(Elf64_Shdr));
        return false;
    }

    shnum = ehdr.e_shnum;
    if (shnum == 0 || shnum > VR_MAX_SECTIONS) {
        logkw(VR_LOG_TAG ": invalid section count=%u\n", shnum);
        return false;
    }
    if (ehdr.e_shstrndx >= shnum) {
        logkw(VR_LOG_TAG ": invalid shstrndx=%u shnum=%u\n", ehdr.e_shstrndx, shnum);
        return false;
    }

    shtab_bytes = (unsigned long)shnum * sizeof(Elf64_Shdr);
    shdrs = vmalloc(shtab_bytes);
    if (!shdrs) {
        logkw(VR_LOG_TAG ": alloc section headers failed size=%lu\n", shtab_bytes);
        return false;
    }
    if (vr_reader_read(reader, ehdr.e_shoff, shdrs, shtab_bytes)) {
        logkw(VR_LOG_TAG ": read section headers failed off=%llu size=%lu\n", ehdr.e_shoff, shtab_bytes);
        goto out;
    }

    shstr_sh = &shdrs[ehdr.e_shstrndx];
    if (shstr_sh->sh_size == 0 || shstr_sh->sh_size > VR_MAX_SHSTRTAB) {
        logkw(VR_LOG_TAG ": invalid shstrtab size=%llu\n", shstr_sh->sh_size);
        goto out;
    }

    shstrtab = vmalloc(shstr_sh->sh_size);
    if (!shstrtab) {
        logkw(VR_LOG_TAG ": alloc shstrtab failed size=%llu\n", shstr_sh->sh_size);
        goto out;
    }
    if (vr_reader_read(reader, shstr_sh->sh_offset, shstrtab, shstr_sh->sh_size)) {
        logkw(VR_LOG_TAG ": read shstrtab failed off=%llu size=%llu\n", shstr_sh->sh_offset, shstr_sh->sh_size);
        goto out;
    }

    for (i = 0; i < shnum; i++) {
        Elf64_Shdr *sh = &shdrs[i];
        const char *name;
        unsigned long remaining;

        if (sh->sh_name >= shstr_sh->sh_size) continue;

        name = shstrtab + sh->sh_name;
        remaining = shstr_sh->sh_size - sh->sh_name;
        if (lib_strnlen(name, remaining) >= remaining) continue;
        if (lib_strcmp(name, ".modinfo") == 0) {
            modinfo_sh = sh;
            break;
        }
    }

    if (!modinfo_sh) {
        logki(VR_LOG_TAG ": .modinfo not found\n");
        goto out;
    }
    if (modinfo_sh->sh_size == 0 || modinfo_sh->sh_size > VR_MAX_MODINFO) {
        logkw(VR_LOG_TAG ": invalid .modinfo size=%llu\n", modinfo_sh->sh_size);
        goto out;
    }

    modinfo = vmalloc(modinfo_sh->sh_size);
    if (!modinfo) {
        logkw(VR_LOG_TAG ": alloc .modinfo failed size=%llu\n", modinfo_sh->sh_size);
        goto out;
    }
    if (vr_reader_read(reader, modinfo_sh->sh_offset, modinfo, modinfo_sh->sh_size)) {
        logkw(VR_LOG_TAG ": read .modinfo failed off=%llu size=%llu\n", modinfo_sh->sh_offset, modinfo_sh->sh_size);
        goto out;
    }

    {
        const char *p = modinfo;
        const char *end = modinfo + modinfo_sh->sh_size;

        while (p < end) {
            const char *nul = lib_memchr(p, '\0', end - p);
            size_t entlen;

            if (!nul) break;

            entlen = nul - p;
            if (entlen > 5 && lib_memcmp(p, "name=", 5) == 0) {
                const char *value = p + 5;
                size_t vlen = entlen - 5;

                if (vlen == 2 && value[0] == 'v' && value[1] == 'r') {
                    is_vr = true;
                    logki(VR_LOG_TAG ": matched module name=vr\n");
                } else {
                    logki(VR_LOG_TAG ": module name is not vr len=%zu\n", vlen);
                }
                break;
            }
            p = nul + 1;
        }
    }

out:
    vfree(modinfo);
    vfree(shstrtab);
    vfree(shdrs);
    return is_vr;
}

static void before_init_module(hook_fargs3_t *args, void *udata)
{
    struct vr_module_reader reader = {
        .umod = (const char __user *)syscall_argn(args, 0),
        .umod_len = (unsigned long)syscall_argn(args, 1),
        .file = 0,
        .file_size = 0,
    };

    logki(VR_LOG_TAG ": init_module enter umod=%llx len=%lu\n", (unsigned long long)reader.umod, reader.umod_len);

    if (!reader.umod || reader.umod_len < sizeof(Elf64_Ehdr)) {
        logkw(VR_LOG_TAG ": init_module invalid args umod=%llx len=%lu\n", (unsigned long long)reader.umod,
              reader.umod_len);
        return;
    }
    if (!kfunc(memdup_user)) {
        logkw(VR_LOG_TAG ": memdup_user unavailable, skip init_module\n");
        return;
    }
    if (!vr_module_is_target(&reader)) return;

    args->skip_origin = 1;
    args->ret = 0;
    logki(VR_LOG_TAG ": blocked vr (init_module)\n");
}

static void before_finit_module(hook_fargs3_t *args, void *udata)
{
    int fd = (int)syscall_argn(args, 0);
    struct file *file;
    struct vr_module_reader reader;
    loff_t file_size;

    logki(VR_LOG_TAG ": finit_module enter fd=%d\n", fd);

    if (!kfunc(fget)) {
        logkw(VR_LOG_TAG ": fget unavailable, skip finit_module\n");
        return;
    }
    if (!kfunc(fput)) {
        logkw(VR_LOG_TAG ": fput unavailable, skip finit_module\n");
        return;
    }
    if (!kfunc(vfs_llseek)) {
        logkw(VR_LOG_TAG ": vfs_llseek unavailable, skip finit_module\n");
        return;
    }
    if (!kfunc(kernel_read)) {
        logkw(VR_LOG_TAG ": kernel_read unavailable, skip finit_module\n");
        return;
    }

    file = kfunc(fget)(fd);
    if (IS_ERR_OR_NULL(file)) {
        logkw(VR_LOG_TAG ": fget failed fd=%d rc=%ld\n", fd, PTR_ERR(file));
        return;
    }

    file_size = vfs_llseek(file, 0, SEEK_END);
    vfs_llseek(file, 0, SEEK_SET);
    logki(VR_LOG_TAG ": finit_module fd=%d size=%lld\n", fd, file_size);
    if (file_size < (loff_t)sizeof(Elf64_Ehdr)) {
        logkw(VR_LOG_TAG ": finit_module invalid size=%lld fd=%d\n", file_size, fd);
        kfunc(fput)(file);
        return;
    }

    reader.umod = 0;
    reader.umod_len = 0;
    reader.file = file;
    reader.file_size = file_size;

    if (vr_module_is_target(&reader)) {
        args->skip_origin = 1;
        args->ret = 0;
        logki(VR_LOG_TAG ": blocked vr (finit_module)\n");
    }

    kfunc(fput)(file);
}

int init_module_filter_init()
{
    hook_err_t err;

    err = fp_hook_syscalln(__NR_init_module, 3, before_init_module, 0, 0);
    log_boot(VR_LOG_TAG ": hook init_module rc: %d\n", err);
    if (err) return err;

    err = fp_hook_syscalln(__NR_finit_module, 3, before_finit_module, 0, 0);
    log_boot(VR_LOG_TAG ": hook finit_module rc: %d\n", err);
    if (err) return err;

    log_boot(VR_LOG_TAG ": installed\n");
    return 0;
}
