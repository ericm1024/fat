/*
 * CS137 fat
 *
 * author: Eric Mueller <emueller@hmc.edu>
 *
 * addapted from first assignment, hellofs
 */

/*
 * TODO:
 *     - implement init
 *         - implement mkfs
 *         - implement mount
 *     - implement getattr
 *         - implement dentry lookup
 *     - implement access
 *     - implement readdir
 *     - implement mkdir
 *         - implement cluster allocation
 */

#define FUSE_USE_VERSION 26

#define _XOPEN_SOURCE 500 /* C sucks */

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 10MiB */
#define FAT_DEFAULT_FS_SIZE (10 * (1 << 20))
#define FAT_DEFAULT_FNAME "fat.dat"

/* cluster and block size are the same for now, but can be changed */
#define FAT_BLOCK_SIZE (512)
#define FAT_CLUSTER_SIZE (1 * FAT_BLOCK_SIZE)

#define packed __attribute__((packed))

#define FAT_SB_MAGIC (0x41615252)

/*
 * on-disk fat superblock
 * 
 * @s_magic         always has the value FAT_SB_MAGIC
 * @s_free          number of free clusters
 * @s_last_allocd   index of the last allocated cluster
 * @s_fat_entries   number of entries in the FAT table
 */
struct packed fat_superblock {
        uint32_t s_magic;
        uint32_t s_free;
        uint32_t s_last_allocd;
        uint32_t s_fat_entries;

        uint8_t __pad[FAT_BLOCK_SIZE - 16];
};

/* maximum filename length. Chosen so dentry size divides block size */
#define FAT_NAME_LEN (22)

/* dentry flags */
#define FAT_DF_RUSR    (0x1u << 0)
#define FAT_DF_WUSR    (0x1u << 1)
#define FAT_DF_XUSR    (0x1u << 2)
#define FAT_DF_RGRP    (0x1u << 3)
#define FAT_DF_WGRP    (0x1u << 4)
#define FAT_DF_XGRP    (0x1u << 5)
#define FAT_DF_ROTH    (0x1u << 6)
#define FAT_DF_WOTH    (0x1u << 7)
#define FAT_DF_XOTH    (0x1u << 8)
#define FAT_DF_FILE    (0x1u << 9)  /* dentry is a file */
#define FAT_DF_DENTRY  (0x1u << 10) /* dentry is another dentry */
#define FAT_DF_DEL     (0x1u << 11) /* dentry has been deleted */
#define FAT_DF_LAST    (0x1u << 12) /* last dentry in dirrectory */

/*
 * on-disk fat directory entry
 *
 * @d_name    filename, null terminated
 * @d_flags   dentry flags, a la FAT_DF_*
 * @d_idx     cluster index of the object described by this dentry
 * @d_fsize   if this dentry describes a file, the field holds its size
 */ 
struct packed fat_dentry {
        char d_name[FAT_NAME_LEN];
        uint16_t d_flags;
        uint32_t d_idx;
        uint32_t d_fsize;
};

#define DENTRIES_PER_CLUSTER (FAT_CLUSTER_SIZE/sizeof(struct fat_dentry))

/*
 * buffer read from the data region of the filesystem
 *
 * @c_fbuf       file buffer -- a piece of a file
 * @c_dentries   block sized array of dentries
 * @c_idx        index of this cluster in the fat table.
 * @c_is_file    true if this cluster is from a file, false if it is dentries
 */ 
struct fat_cluster {
        union {
                uint8_t c_fbuf[FAT_CLUSTER_SIZE];
                struct fat_dentry c_dentries[DENTRIES_PER_CLUSTER];
        };
        uint32_t c_idx;
        bool c_is_file;
};

#define FAT_END_MARK  0xffffffff
#define FAT_BAD_MARK  0xfffffff7
#define FAT_FREE_MARK 0x0

/*
 * in-memory glob of all datat structures necessary to operate on a fat
 * filesystem
 *
 * @f_fat          the file allocation table
 *
 * @f_flist_size   number of used/valid entries in f_flist_vec
 * @f_flist_cap    number of allocated entries in f_flist_vec;
 * @f_flist_vec    vector of free cluster indicies
 *
 * @f_sb           fat superblock
 * @f_fd           file descriptor of the backing device for this filesystem
 */ 
struct fat_fs {
        /* fat table */
        uint32_t *f_fat;

        /* freelist stuff */
        uint32_t f_flist_size;
        uint32_t f_flist_cap;
        uint32_t *f_flist_vec;

        struct fat_superblock *f_sb;
        int f_fd;
};

static struct fat_fs global_fat_fs;

/*
 * common error reporting function in case we ever want to write to a log
 * file or something fancy
 */ 
static void fat_error(const char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, "\n");
}

/*
 * common tracing function so we can enable/disable tracing based on
 * compliation/runtime arguments
 */ 
static void fat_trace(const char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, "\n");
}

/* is this cluster number actually allocated in the fat? */ 
static bool fat_cluster_is_allocated(const struct fat_fs *fs, uint32_t idx)
{
        assert(idx <= fs->f_sb->s_fat_entries);
        return fs->f_fat[idx] != FAT_FREE_MARK;
}

/* is this dentry a file? */
static bool fat_dentry_is_file(const struct fat_dentry *d)
{
        return d->d_flags & FAT_DF_FILE;
}

/* is this dentry another dentry? */
static bool fat_dentry_is_dentry(const struct fat_dentry *d)
{
        return d->d_flags & FAT_DF_DENTRY;
}

/* is this dentry deleted? */
static bool fat_dentry_is_del(const struct fat_dentry *d)
{
        return d->d_flags & FAT_DF_DEL;
}

/* is this dentry the last dentry in a directory? */
static bool fat_dentry_is_last(const struct fat_dentry *d)
{
        return d->d_flags & FAT_DF_LAST;
}

/* follow a chain in the fat */
static uint32_t fat_follow_chain(uint32_t idx, const struct fat_fs *fs)
{
        assert(idx <= fs->f_sb->s_fat_entries);
        return fs->f_fat[idx];
}

/*
 * add a cluster index to the in memory freelist. Note that this does
 * NOT modify the in-memory or on disk fat table
 *
 * @fs    fat filesystem instance
 * @idx   index of unallocated cluster to add
 *
 * @returns 0 on success, -ENOMEM on failure
 */ 
static int fat_flist_push(struct fat_fs *fs, uint32_t idx)
{
        assert(!fat_cluster_is_allocated(fs, idx));
        
        if (fs->f_flist_size == fs->f_flist_cap) {
                uint32_t *new_flist = realloc(fs->f_flist_vec,
                                              fs->f_flist_cap*2);
                if (!new_flist)
                        return -ENOMEM;
                fs->f_flist_vec = new_flist;
                fs->f_flist_cap *= 2;
        }

        fs->f_flist_vec[fs->f_flist_size++] = idx;
        return 0;
}

/*
 * get a free cluster index from the in-memory freelist
 *
 * @parm fs   fat filesystem index
 *
 * @returns the index of a free cluster
 */ 
static uint32_t fat_flist_pop(struct fat_fs *fs)
{
        assert(fs->f_flist_size > 0);
        return fs->f_flist_vec[fs->f_flist_size--];
}

/* predicate to determine if a fat has free space */
static bool fat_has_free_clusters(const struct fat_fs *fs)
{
        return fs->f_flist_size > 0;
}

/*
 * determine if the next level in a path matches the name of a given dentry
 *
 * @path   the path to compare. must have a leading '/'
 * @d      the dentry to examine
 *
 * @returns true if the paths match, false otherwise
 *
 * This might not be the most efficient implementation of this function,
 * but ideally it is "clear and obviously correct"
 */ 
static bool fat_path_matches_dentry(const char *path,
                                    const struct fat_dentry *d)
{
        size_t path_level_len;
        size_t d_name_len;

        assert(*path);
        assert(*path == '/');

        /* walk past leading '/' */
        path++;
        
        path_level_len = strchr(path, '/') ? strchr(path, '/') - path
                                           : strlen(path);
        d_name_len = strlen(d->d_name);

        if (path_level_len != d_name_len)
                return false;
        else
                return !strncmp(path, d->d_name, d_name_len);
}

/*
 * Move a pointer to a path string to the next '/' in a path. the path
 * must contain a '/'.
 *
 * @pathp   Pointer to path string. *pathp must start with '/'. If the path
 *          contains another non-trailing slash, the path is pointed to that
 *          slash.
 * 
 * @returns true if the path had another level, false if the path was a leaf
 */ 
static bool fat_path_eat_level(const char **pathp)
{
        const char *path = *pathp;
        char *slash;
        assert(*path);
        assert(*path == '/');

        /* walk past leading '/' */
        path++;

        /* find the next '/' */
        slash = strchr(path, '/');

        /*
         * if there is no next '/' or the character after the next '/' is a
         * null byte (i.e. the slash is trailing), then this is a leaf path
         */
        if (!slash || !*++slash)
                return false;

        *pathp = slash;
        return true;
}

/*
 * block writing implementation function. The only difference between this
 * and fat_write_blocks is this function takes a file descriptor instead of
 * a struct fat_fs so that it can be used before we've constructed
 * a struct fat_fs (i.e. in fat_mkfs)
 *
 * all writes go through this function.
 */ 
static int __fat_write_blocks(off_t offset, int fd, size_t size,
                              const void *block)
{
        ssize_t ret = pwrite(fd, block, size, offset);
        int err = 0;

        /*
         * assignment requires we treat backing deivce like a disk, so
         * assert that we do so.
         */
        assert(size%FAT_BLOCK_SIZE == 0);
        assert(offset%FAT_BLOCK_SIZE == 0);

        if (ret < 0) {
                err = -errno;
                fat_error("%s: pwrite failed with %s", __func__,
                          strerror(errno));
        } else if ((size_t)ret < size) {
                fat_error("%s: short pwrite at offset=%ld. size=%ld",
                          __func__, offset, ret);
                err = -EIO; /* XXX: better error? */
        }
        return err;
}

/*
 * write blocks to the backing device.
 *
 * @offset   byte offset into the backing device to read from.
 * @fs       fat filesystem instance
 * @size     number of bytes to read
 * @block    input buffer
 *
 * @returns 0 on success, negative values on error.
 */ 
static int fat_write_blocks(off_t offset, struct fat_fs *fs,
                            size_t size, const void *block)
{
        return __fat_write_blocks(offset, fs->f_fd, size, block);
}

/*
 * read blocks from the backing device. All reads go through this
 * function.
 *
 * @offset   byte offset into the backing device to read from. must be
 *           divisible by FAT_BLOCK_SIZE
 * @fs       fat filesystem instance
 * @size     number of bytes to read
 * @block    output buffer
 *
 * @returns 0 on success, negative values on error.
 */ 
static int fat_read_blocks(off_t offset, const struct fat_fs *fs,
                           size_t size, void *block)
{
        ssize_t ret = pread(fs->f_fd, block, size, offset);
        int err = 0;

        /*
         * assignment requires we treat backing deivce like a disk, so
         * assert that we do so.
         */
        assert(size%FAT_BLOCK_SIZE == 0);
        assert(offset%FAT_BLOCK_SIZE == 0);

        if (ret < 0) {
                err = -errno;
                fat_error("%s: pread failed with %s", __func__,
                          strerror(errno));
        } else if ((size_t)ret < size) {
                fat_error("%s: short pread at offset=%ld. size=%ld",
                          __func__, offset, ret);
                err = -EIO; /* XXX: better error? */
        }
        return err;
}

/*
 * read a single cluster from the data segment of a fat filesystem
 *
 * @cluster  the in-memory representation of the cluster to read
 * @fs       fat instance
 *
 * @returns 0 on success, or negative errors on failure, including if the
 * cluster has not been allocated
 */ 
static int fat_read_cluster(struct fat_cluster *cluster,
                            const struct fat_fs *fs)
{
        off_t offset = sizeof(struct fat_superblock)
                + sizeof(uint32_t)*fs->f_sb->s_fat_entries
                + FAT_CLUSTER_SIZE*cluster->c_idx;

        if (!fat_cluster_is_allocated(fs, cluster->c_idx))
                return -ENOENT;
        return fat_read_blocks(offset, fs, FAT_CLUSTER_SIZE, &cluster->c_fbuf);
}

/*
 * Lookup a dentry corresponding to path, starting at parent.
 *
 * @path     path to lookup dentry for. should start with a '/'
 * @parent   parent dentry if already looked up, can be NULL
 * @fs       fat instance
 * @out_d    the resulting dentry is written here
 *
 * @returns 0 on success, negative values on error.
 * 
 * This function is implemented recursively.
 */ 
static int fat_get_dentry(const char *path, const struct fat_dentry *parent,
                          const struct fat_fs *fs, struct fat_dentry *out_d)
{
        struct fat_cluster cluster;

        cluster.c_is_file = false;
        cluster.c_idx = parent ? parent->d_idx : 0;

        fat_trace("%s: path='%s', parent=%p", __func__, path, (void*)parent);
        
        if (!*path || *path != '/')
                return -EINVAL;

        for (;;) {
                unsigned i;
                int err;
                uint32_t next_idx;

                /* read the next cluster of dentries in this directory */
                err = fat_read_cluster(&cluster, fs);
                if (err)
                        return err;

                /* look for a dentry in the cluster that matches @path */
                for (i = 0; i < DENTRIES_PER_CLUSTER; ++i) {
                        struct fat_dentry *d = &cluster.c_dentries[i];
                        
                        if (fat_dentry_is_last(d))
                                return -ENOENT;
                        else if (fat_dentry_is_del(d))
                                continue;

                        if (fat_path_matches_dentry(path, d)) {
                                if (!fat_path_eat_level(&path)) {
                                        *out_d = *d;
                                        fat_trace("%s: found dentry in "
                                                  "cluster=%u, dname=%s, "
                                                  "index=%u", __func__,
                                                  cluster.c_idx, d->d_name,
                                                  i);
                                        return 0;
                                }
                                return fat_get_dentry(path, d, fs, out_d);
                        }
                }

                next_idx = fat_follow_chain(cluster.c_idx, fs);
                /*
                 * we shouldn't need the fat to tell us that we got to the
                 * end of a directory. the last dentry should be marked as
                 * last, so the above loop should catch it. thus if we get
                 * here, we have a bug.
                 */ 
                if (next_idx == FAT_END_MARK) {
                        fat_error("%s: directory has no last dentry. idx=%d",
                                  __func__, cluster.c_idx);
                        return -EIO; /* XXX: better error? or panic? */
                }
                cluster.c_idx = next_idx;
        }
}

/*
 * initialize a file to look like a fat filesystem, i.e. truncate the file,
 * construct a superblock, and write out that superblock
 *
 * @fd     The file descriptor to write to
 * @size   The size of the filesystem to make
 *
 * @returns 0 on success, negative values on errors
 */ 
static int fat_mkfs(int fd, size_t size)
{
        int err;
        struct fat_superblock *sb;
        /* nasty math to make sure that the fat is block alligned */
        uint32_t entries_per_block = FAT_BLOCK_SIZE/sizeof(uint32_t);
        uint32_t nr_fat_entries =
                ((size - FAT_BLOCK_SIZE)  
                 /(entries_per_block*(sizeof(uint32_t)+FAT_CLUSTER_SIZE)))
                 * entries_per_block;

        /*
         * XXX: currently we just choose the number of entries in the FAT
         * so that it is block-alligned. However, this yields unadressable
         * clusters at the end of the filesystem. We should really make
         * the fat one block larger and then mark the out of range entries
         * at the end of the fat as not allocatable with FAT_BAD_MARK
         */

        /* sanity check our math */
        /* fat table size should divide block size*/
        assert((nr_fat_entries*sizeof(uint32_t))%FAT_BLOCK_SIZE == 0);
        /* superblock + fat + clusters fit in fs size */
        assert(FAT_BLOCK_SIZE +
               nr_fat_entries*(FAT_CLUSTER_SIZE + sizeof(uint32_t))
               <= FAT_DEFAULT_FS_SIZE);

        fat_trace("%s: fs_size=%u, nr_fat_entries=%u", size, nr_fat_entries);

        err = ftruncate(fd, size);
        if (err)
                return -errno;

        sb = malloc(sizeof *sb);
        if (!sb)
                return -ENOMEM;

        memset(sb, 0, sizeof *sb);
        sb->s_magic = FAT_SB_MAGIC;
        sb->s_free = nr_fat_entries;
        sb->s_last_allocd = 0;
        sb->s_fat_entries = nr_fat_entries;

        err = __fat_write_blocks(0, fd, FAT_BLOCK_SIZE, sb);
        if (err)
                return err;

        /* XXX: allocate root dentry? */
        return 0;
}

/*
 * validate a superblock
 *
 * @sb   the superblock to validate
 *
 * @returns 0 on success, negative values on error.
 */ 
static int fat_verify_sb(struct fat_superblock *sb)
{
        /*
         * we can probably do better verification than this, but
         * it won't be constant time
         */
        return sb->s_magic == FAT_SB_MAGIC ? 0 : -EIO;
}

/*
 * initialize a fat_fs structure by reading reading and parsing a backing
 * file.
 *
 * @bfile_name   The name of the backing file that contains the filesystem.
 *               A file with this name is created and initialized if one
 *               does not exist.
 * @fs           The filesystem instance to fill
 *
 * @returns 0 on success, negative error values on error.
 *
 * This function does 4 major things:
 *     1. opening/creating the backing file, and doing a 'mkfs' if it had
 *        to be created
 *     2. allocate, read, and verify the superblock
 *     3. read the fat
 *     4. construct the freelist
 */ 
static int fat_fill_fs(const char *bfile_name, struct fat_fs *fs)
{
        uint32_t *fat, *flist_vec, fat_size, flist_cap, i;
        int err;
        int fd;
        struct fat_superblock *sb;

        memset(fs, 0, sizeof *fs);

        /*
         * step 1: open the backing file. if it does not exist, open it
         * and create a fat filesystem in it.
         */
        err = access(bfile_name, F_OK);
        if (err) {
                if (errno != ENOENT) {
                        err = -errno;
                        fat_error("%s: could not access %s: %s", __func__,
                                  bfile_name, strerror(errno));
                        goto out_err;
                }
                fd = open(bfile_name, O_RDWR|O_CREAT, 0644);
                if (fd < 0) {
                        err = -errno;
                        fat_error("%s: could not open %s for creation: %s",
                                  __func__, bfile_name, strerror(errno));
                        goto out_err;
                }
                err = fat_mkfs(fd, FAT_DEFAULT_FS_SIZE);
                if (err) {
                        fat_error("%s: mkfs failed: %s", __func__,
                                  strerror(-err));
                        goto out_close;
                }
        } else {
                fd = open(bfile_name, O_RDWR);
                if (fd < 0) {
                        err = -errno;
                        fat_error("%s: could not open %s: %s",
                                  __func__, bfile_name, strerror(errno));
                        goto out_err;
                }
        }

        fs->f_fd = fd;
        fat_trace("%s: successfully opened file %s", __func__, bfile_name);

        /* step 2: allocate, read, and verify the superblock */
        sb = malloc(sizeof *sb);
        if (!sb) {
                err = -ENOMEM;
                fat_error("%s: could not allocate superblock", __func__);
                goto out_close;
        }
        err = fat_read_blocks(0, fs, FAT_BLOCK_SIZE, sb);
        if (err)
                goto out_free_sb;

        err = fat_verify_sb(sb);
        if (err)
                goto out_free_sb;

        fs->f_sb = sb;
        fat_trace("%s: read and verified superblock", __func__);

        /* step 3: allocate and read fat */
        fat_size = sb->s_fat_entries * sizeof *fat;
        fat = malloc(fat_size);
        if (!fat) {
                err = -ENOMEM;
                fat_error("%s: failed to allocate fat of size %zu",
                          __func__, fat_size);
                goto out_free_sb;
        }

        err = fat_read_blocks(FAT_BLOCK_SIZE, fs, fat_size, fat);
        if (err)
                goto out_free_fat;

        fs->f_fat = fat;
        fat_trace("%s: read fat with %u entries", __func__, sb->s_fat_entries);

        /* step 4: generate freelist */
        flist_cap = sb->s_free;
        flist_vec = malloc(flist_cap * sizeof *flist_vec);
        if (!flist_vec) {
                err = -ENOMEM;
                fat_error("%s: failed to allocate freelist of size %zu",
                          __func__, flist_cap);
                goto out_free_fat;
        }

        fs->f_flist_vec = flist_vec;
        fs->f_flist_cap = flist_cap;
        fs->f_flist_size = 0;

        for (i = 0; i < sb->s_fat_entries; ++i) {
                if (fs->f_fat[i] == FAT_FREE_MARK) {
                        err = fat_flist_push(fs, i);
                        if (err)
                                goto out_free_freelist;
                }
        }

        /*
         * make sure the number of free clusters we found agrees with
         * the number in the superblock
         */
        if (fs->f_flist_size != fs->f_sb->s_free) {
                err = -EIO; /* XXX: better error? */
                goto out_free_freelist;
        }

        fat_trace("%s: generated freelist with %u entries", __func__,
                  fs->f_flist_size);

        /* XXX: do more intense fsck'ing here? */

        return 0;

out_free_freelist:
        free(flist_vec);
out_free_fat:
        free(fat);
out_free_sb:
        free(sb);
out_close:
        close(fd);
out_err:
        memset(fs, 0, sizeof *fs);
        return err;
}

static int fat_getattr(const char *path, struct stat *stbuf)
{
        return -ENOSYS;
}

static int fat_access(const char *path, int mask)
{
        return -ENOSYS;
}

static int fat_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
        return -ENOSYS;
}

static int fat_truncate(const char *path, off_t size)
{
        return -ENOSYS;
}

static int fat_open(const char *path, struct fuse_file_info *fi)
{
        return -ENOSYS;
}

static int fat_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
        return -ENOSYS;
}

static int fat_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
        return -ENOSYS;
}

static int fat_readlink(const char *path, char *buf, size_t size)
{
        return -ENOSYS;
}

static int fat_mknod(const char *path, mode_t mode, dev_t rdev)
{
        return -ENOSYS;
}

static int fat_mkdir(const char *path, mode_t mode)
{
        return -ENOSYS;
}

static int fat_unlink(const char *path)
{
        return -ENOSYS;
}

static int fat_rmdir(const char *path)
{
        return -ENOSYS;
}

static int fat_symlink(const char *to, const char *from)
{
        return -ENOSYS;
}

static int fat_rename(const char *from, const char *to)
{
        return -ENOSYS;
}

static int fat_link(const char *from, const char *to)
{
        return -ENOSYS;
}

static int fat_chmod(const char *path, mode_t mode)
{
        return -ENOSYS;
}

static int fat_chown(const char *path, uid_t uid, gid_t gid)
{
        return -ENOSYS;
}

static int fat_utimens(const char *path, const struct timespec ts[2])
{
        return -ENOSYS;
}

static int fat_statfs(const char *path, struct statvfs *stbuf)
{
        return -ENOSYS;
}

static struct fuse_operations fat_oper = {
	.getattr        = fat_getattr,
	.access		= fat_access,
	.readlink	= fat_readlink,
	.readdir	= fat_readdir,
	.mknod		= fat_mknod,
	.mkdir		= fat_mkdir,
	.symlink	= fat_symlink,
	.unlink		= fat_unlink,
	.rmdir		= fat_rmdir,
	.rename		= fat_rename,
	.link		= fat_link,
	.chmod		= fat_chmod,
	.chown		= fat_chown,
	.truncate	= fat_truncate,
	.utimens	= fat_utimens,
	.open		= fat_open,
	.read		= fat_read,
	.write		= fat_write,
	.statfs		= fat_statfs,
};

int main(int argc, char *argv[])
{
        int err;
	umask(0); /* XXX: why is this here? */
        err = fat_fill_fs(FAT_DEFAULT_FNAME, &global_fat_fs);
        if (err)
                return -err;
	return fuse_main(argc, argv, &fat_oper, NULL);
}
