/*
 * CS137 fat
 *
 * author: Eric Mueller <emueller@hmc.edu>
 *
 * Currently this implements access(), getattr(), mkdir(), and readdir()
 *
 * Directory size is only limited by filesystem size.
 */

/*
 * issues:
 *    directories don't shrink as dentries are removed
 *    code duplication in mkdir/symlink/mknod
 *    code duplication in read/write
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
#include <stddef.h>
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

/* dentry flags */
#define FAT_DF_FILE    (0x1u << 0) /* dentry is a file */
#define FAT_DF_DENTRY  (0x1u << 1) /* dentry is another dentry */
#define FAT_DF_DEL     (0x1u << 2) /* dentry has been deleted */
#define FAT_DF_LAST    (0x1u << 3) /* last dentry in dirrectory */
#define FAT_DF_LINK    (0x1u << 4) /* symlink */

/* maximum filename length. Chosen so dentry size divides block size */
#define FAT_NAME_LEN (50)

/*
 * on-disk fat directory entry
 *
 * @d_name    filename, null terminated
 * @d_flags   dentry flags, a la FAT_DF_*
 * @d_idx     cluster index of the object described by this dentry
 * @d_fsize   if this dentry describes a file, the field holds its size
 * @d_nlink   number of hardlinks to this dentry.
 */ 
struct packed fat_dentry {
        char d_name[FAT_NAME_LEN];
        uint16_t d_flags;
        uint32_t d_idx;
        uint32_t d_fsize;
        uint32_t d_nlink;
};

#define FAT_DENTRIES_PER_CLUSTER (FAT_CLUSTER_SIZE/sizeof(struct fat_dentry))

/*
 * buffer read from the data region of the filesystem
 *
 * @c_fbuf       file buffer -- a piece of a file
 * @c_dentries   block sized array of dentries
 * @c_idx        index of this cluster in the fat table.
 */ 
struct fat_cluster {
        union {
                uint8_t c_fbuf[FAT_CLUSTER_SIZE];
                struct fat_dentry c_dentries[FAT_DENTRIES_PER_CLUSTER];
        };
        uint32_t c_idx;
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
 * dentry iterator used to walk through a dentry
 *
 * @di_fs        The filesystem instance we're operating on.
 * @di_cluster   Cluster buffer. Dynamically allocated.
 * @di_d_index   Which dentry in the current cluster does this iterator
 *               represent?
 */ 
struct fat_diter {
        struct fat_fs *di_fs;
        struct fat_cluster *di_cluster;
        unsigned di_d_index;
};

static int fat_alloc_cluster(uint32_t parent, struct fat_fs *fs, uint32_t *out);

/*
 * this makes the compiler type-check format strings for functions that
 * behave like printf, because frankly I always mess them up.
 * eg, before I included this, my code was segfaulting
 */ 
#define __printf_like(fmt, args) \
        __attribute__((format(printf, fmt, args)))

/* common error reporting function */
static void __printf_like(1, 2) fat_error(const char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, "\n");
        /*exit(1)*/
}

/* common tracing function */
static void __printf_like(1, 2) fat_trace(const char *fmt, ...)
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
        return idx < fs->f_sb->s_fat_entries
                && fs->f_fat[idx] != FAT_FREE_MARK;
}

/* is this dentry is a symlink? */
static bool fat_dentry_is_link(const struct fat_dentry *d)
{
        return d->d_flags & FAT_DF_LINK;
}

/* is this dentry a file? */
static bool fat_dentry_is_file(const struct fat_dentry *d)
{
        return d->d_flags & FAT_DF_FILE;
}

/* is this dentry another dentry? */
static bool fat_dentry_is_dir(const struct fat_dentry *d)
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

/* clear a dentry flag */
static void fat_dentry_clear_flag(uint16_t flag, struct fat_dentry *d)
{
        d->d_flags &= ~flag;
}

/* set a dentry flag */
static void fat_dentry_set_flag(uint16_t flag, struct fat_dentry *d)
{
        d->d_flags |= flag;
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
        return fs->f_flist_vec[--fs->f_flist_size];
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

        /* base case: match root dentry */
        if (strlen(d->d_name) == 0)
                return true;

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
static bool fat_path_eat_level(const char **pathp,
                               const struct fat_dentry *d)
{
        const char *path = *pathp;
        char *slash;
        assert(*path);
        assert(*path == '/');

        /* root dentry has empty d_name, so do nothing */
        if (strlen(d->d_name) == 0 && strlen(*pathp) != 1)
                return true;

        /* walk past leading '/' */
        path++;

        /* find the next '/' */
        slash = strchr(path, '/');

        /*
         * if there is no next '/' or the character after the next '/' is a
         * null byte (i.e. the slash is trailing), then this is a leaf path
         */
        if (!slash || !*(slash+1))
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
                fat_error("%s: short pwrite at offset=%ld size=%ld",
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
static int fat_write_blocks(off_t offset, const struct fat_fs *fs,
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
                fat_error("%s: short pread at offset=%ld size=%ld",
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
 * write a single cluster to the data segment of a fat filesystem
 *
 * @cluster  The cluster to write
 * @fs       fat instance to write to
 *
 * @returns 0 on success, ngative errors on falure
 */ 
static int fat_write_cluster(const struct fat_cluster *cluster,
                             const struct fat_fs *fs)
{
        off_t offset = sizeof(struct fat_superblock)
                + sizeof(uint32_t)*fs->f_sb->s_fat_entries
                + FAT_CLUSTER_SIZE*cluster->c_idx;

        if (!fat_cluster_is_allocated(fs, cluster->c_idx))
                return -ENOENT;
        return fat_write_blocks(offset, fs, FAT_CLUSTER_SIZE, &cluster->c_fbuf);
}

static int fat_diter_begin(struct fat_diter *di,
                           const struct fat_dentry *parent)
{
        int ret;
        uint32_t d_idx = parent ? parent->d_idx : 0;

        di->di_cluster = malloc(sizeof *di->di_cluster);
        if (!di->di_cluster)
                return -ENOMEM;
        memset(di->di_cluster, 0, sizeof *di->di_cluster);
        if (!fat_cluster_is_allocated(di->di_fs, d_idx)) {
                free(di->di_cluster);
                return -ENOENT;
        }        
        di->di_cluster->c_idx = d_idx;
        ret = fat_read_cluster(di->di_cluster, di->di_fs);
        if (ret) {
                free(di->di_cluster);
                return ret;
        }        
        di->di_d_index = 0;
        return 0;
}

static struct fat_dentry *fat_diter_get(const struct fat_diter *di)
{
        return &di->di_cluster->c_dentries[di->di_d_index];
}

static int fat_diter_advance_cluster(struct fat_diter *di)
{
        int ret;
        uint32_t idx = fat_follow_chain(di->di_cluster->c_idx,
                                        di->di_fs);
        if (idx == FAT_END_MARK)
                return -ENOENT;
        di->di_cluster->c_idx = idx;
        ret = fat_read_cluster(di->di_cluster, di->di_fs);
        if (ret)
                return ret;
        di->di_d_index = 0;
        return ret;
}

static int fat_diter_advance_force(struct fat_diter *di)
{
        int ret;
        if (di->di_d_index < FAT_DENTRIES_PER_CLUSTER - 1) {
                di->di_d_index++;
                return 0;
        }
        di->di_cluster->c_idx = fat_follow_chain(di->di_cluster->c_idx,
                                                 di->di_fs);
        ret = fat_read_cluster(di->di_cluster, di->di_fs);
        if (ret)
                return ret;
        di->di_d_index = 0;
        return 0;
}
        
static int fat_diter_advance(struct fat_diter *di)
{
        struct fat_dentry *d = fat_diter_get(di);
        if (fat_dentry_is_last(d))
                return -ENOENT;
        return fat_diter_advance_force(di);
}

static void fat_diter_end(struct fat_diter *di)
{
        free(di->di_cluster);
        di->di_cluster = NULL;
}

static int fat_diter_clone(const struct fat_diter *parent,
                           struct fat_diter *child)
{
        size_t csize = sizeof *child->di_cluster;
        child->di_fs = parent->di_fs;
        child->di_d_index = parent->di_d_index;
        child->di_cluster = malloc(csize);
        if (!child->di_cluster)
                return -ENOMEM;
        memcpy(child->di_cluster, parent->di_cluster, csize);
        return 0;
}

static int fat_diter_alloc_cluster(struct fat_diter *diter)
{
        assert(diter->di_d_index == FAT_DENTRIES_PER_CLUSTER - 1);
        assert(fat_dentry_is_last(fat_diter_get(diter)));
        return fat_alloc_cluster(diter->di_cluster->c_idx, diter->di_fs, NULL);
}

static int fat_diter_commit(const struct fat_diter *diter)
{
        return fat_write_cluster(diter->di_cluster, diter->di_fs);
}

/*
 * Lookup a dentry itterator corresponding to path, starting at parent.
 *
 * @path     path to lookup dentry for. should start with a '/'
 * @parent   parent dentry if already looked up, can be NULL
 * @fs       fat instance
 * @out_d    the resulting dentry is written here. Note that this MUST
 *           BE FREE'D using fat_diter_end
 *
 * @returns 0 on success, negative values on error.
 * 
 * This function is implemented recursively.
 */ 
static int __fat_get_diter(const char *path, const struct fat_dentry *parent,
                           struct fat_fs *fs, struct fat_diter *out_d)
{
        struct fat_diter diter;
        int err;

        if (!*path || *path != '/')
                return -EINVAL;

        if (parent && !fat_dentry_is_dir(parent)) {
                printf("%s bombed\n", __func__);
                return -ENOTDIR;
        }

        diter.di_fs = fs;
        err = fat_diter_begin(&diter, parent);
        if (err)
                return err;

        for (;;) {
                struct fat_dentry *d = fat_diter_get(&diter);
                
                if (!fat_dentry_is_del(d)
                    && fat_path_matches_dentry(path, d)) {
                        if (!fat_path_eat_level(&path, d)) {
                                *out_d = diter;
                                return 0;
                        }
                        err = __fat_get_diter(path, d, fs, out_d);
                        goto out_free_diter;
                }
               
                err = fat_diter_advance(&diter);
                if (err)
                        goto out_free_diter;
        }
out_free_diter:
        fat_diter_end(&diter);
        return err;
}

/* see __fat_get_diter */
static int fat_get_diter(const char *path, struct fat_fs *fs,
                         struct fat_diter *out)
{
        return __fat_get_diter(path, NULL, fs, out);
}

/*
 * Lookup a dentry without getting the whole directory iterator.
 * Good for doing read-only things with dentries, but not useful
 * for read/write as a dentry doesn't itself have enough information
 * to know where to be written to disk.
 */ 
static int fat_get_dentry(const char *path, struct fat_fs *fs,
                          struct fat_dentry *out)
{
        struct fat_diter diter;
        int err = fat_get_diter(path, fs, &diter);
        if (err)
                return err;
        *out = *fat_diter_get(&diter);
        fat_diter_end(&diter);
        return 0;
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
        struct fat_cluster cluster;
        struct fat_dentry *root_dentry;
        uint32_t fat_block[FAT_BLOCK_SIZE/sizeof(uint32_t)];

        fat_trace("%s: called", __func__);

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

        fat_trace("%s: fs_size=%zu, nr_fat_entries=%u", __func__, size,
                  nr_fat_entries);

        err = ftruncate(fd, size);
        if (err)
                return -errno;

        sb = malloc(sizeof *sb);
        if (!sb)
                return -ENOMEM;

        memset(sb, 0, sizeof *sb);
        sb->s_magic = FAT_SB_MAGIC;
        sb->s_free = nr_fat_entries - 1;
        sb->s_last_allocd = 0;
        sb->s_fat_entries = nr_fat_entries;

        fat_trace("%s: about to write superblock", __func__);
        
        err = __fat_write_blocks(0, fd, FAT_BLOCK_SIZE, sb);
        if (err)
                return err;

        /*
         * write the root dentry. we have to do this "by hand" because
         * the generic dentry-writing function requires a struct fat_fs,
         * which we don't have yet. In the same vein, we have to mark this
         * cluster in the fat as allocated
         */
        memset(&cluster, 0, sizeof cluster);
        root_dentry = &cluster.c_dentries[0];
        root_dentry->d_name[0] = '\0';
        fat_dentry_set_flag(FAT_DF_LAST|FAT_DF_DENTRY, root_dentry);
        root_dentry->d_idx = FAT_END_MARK;
        root_dentry->d_fsize = 0;
        root_dentry->d_nlink = 2;

        err = __fat_write_blocks(nr_fat_entries*sizeof(uint32_t)
                                 + FAT_BLOCK_SIZE, fd,
                                 sizeof cluster.c_dentries,
                                 &cluster.c_dentries);
        if (err)
                return err;

        memset(fat_block, 0, sizeof fat_block);
        fat_block[0] = FAT_END_MARK;
        return __fat_write_blocks(FAT_BLOCK_SIZE, fd, FAT_BLOCK_SIZE,
                                  fat_block);
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
 * initialize a fat_fs structure by reading and parsing a backing file.
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
                fd = open(bfile_name, O_RDWR|O_CREAT|O_EXCL, 0644);
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
                fat_error("%s: failed to allocate fat of size %u",
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
                fat_error("%s: failed to allocate freelist of size %u",
                          __func__, flist_cap);
                goto out_free_fat;
        }

        fs->f_flist_vec = flist_vec;
        fs->f_flist_cap = flist_cap;
        fs->f_flist_size = 0;

        if (fs->f_fat[0] == FAT_FREE_MARK) {
                fat_error("%s: cluster 0 should be alloc'd for root dentry",
                          __func__);
                err = -EIO;
                goto out_free_freelist;
        }
        
        for (i = sb->s_fat_entries; i-- > 0; ) {
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
        fat_error("%s: %s", __func__, strerror(-err));
        return err;
}

/*
 * Commit a change to the fat, i.e. change the value at an index to a new
 * value and commit it to stable storage.
 *
 * @idx   The index in the fat to change.
 * @new   The new value to write at that index.
 * @fs    The filesystem instance to modify.
 *
 * @return We don't return anything here because it's difficult to
 * reason about what to "un-modify" if a IO fails during a fat modification,
 * so if an IO does fail we just yell loudly
 */ 
static void fat_modify_fat(uint32_t idx, uint32_t new, struct fat_fs *fs)
{
        int ret;
        ptrdiff_t fat_off = FAT_BLOCK_SIZE*((idx*sizeof idx)/FAT_BLOCK_SIZE);
        off_t file_off = fat_off + FAT_BLOCK_SIZE; /* account for sb */
        assert(idx < fs->f_sb->s_fat_entries);

        fat_trace("%s: committing fat change at idx=%u: old=%u, new=%u, "
                  "file_off=%lu", __func__, idx, fs->f_fat[idx],
                  new, file_off);

        fs->f_fat[idx] = new;
        ret = fat_write_blocks(file_off, fs, FAT_BLOCK_SIZE,
                               (uint8_t *)fs->f_fat + fat_off);

        /* XXX: don't be lazy here, actually handle this */
        if (ret)
                fat_error("%s: write failed. This error is unhandled!",
                          __func__);
}

/* write out the superblock */ 
static int fat_commit_sb(const struct fat_fs *fs)
{
        return fat_write_blocks(0, fs, FAT_BLOCK_SIZE, fs->f_sb);
}

/*
 * Allocate a cluster on-disk and return the index of the new allocated
 * cluster.
 *
 * @parent   The index of the previous cluster in the chain, or FAT_END_MARK
 *           if this is the first cluster in the chain.
 * @fs       The filesystem instance to allocate in.
 * @out      The cluster number we allocated
 *
 * @returns 0 on success, negative values on error 
 */
static int fat_alloc_cluster(uint32_t parent, struct fat_fs *fs, uint32_t *out)
{
        uint32_t new_cl;
        int err;

        if (!fat_has_free_clusters(fs))
                return -ENOSPC;

        new_cl = fat_flist_pop(fs);
        fat_modify_fat(new_cl, FAT_END_MARK, fs);

        if (parent != FAT_END_MARK) {
                assert(fat_cluster_is_allocated(fs, parent));
                fat_modify_fat(parent, new_cl, fs);
        }

        fs->f_sb->s_free--;
        fs->f_sb->s_last_allocd = new_cl;
        err = fat_commit_sb(fs);
        if (err)
                /* xxx: metadata inconsistency */
                return err;
        
        if (out)
                *out = new_cl;
        fat_trace("%s: allocated cluster %u", __func__, new_cl);
        return 0;
}

/*
 * free a cluster from the fat, adding it to the free list, etc.
 *
 * @idx    cluster index to free
 * @fs     filesystem instance to free from
 *
 * @returns 0 on success, negative values on error.
 */ 
static int fat_free_cluster(uint32_t idx, struct fat_fs *fs)
{
        int err;

        fat_trace("%s: freeing cluster %u", __func__, idx);
        
        fat_modify_fat(idx, FAT_FREE_MARK, fs);
        err = fat_flist_push(fs, idx);
        if (err)
                return err;
        
        fs->f_sb->s_free++;
        err = fat_commit_sb(fs);
        if (err) {
                fs->f_sb->s_free--;
                return err;
        }
        return err;
}

/*
 * allocate space for and commit a new dentry given a parent dentry.
 *
 * @dentry   The dentry to write.
 * @parent   The 
 * @fs       The fat filesystem instance to operate on.
 *
 * @returns 0 on success, negative values on error
 *
 * This function walks through the directory described by 'parent' and looks for
 * a suitable spot to place the new dentry. There are several cases here:
 *     (1) The annoying base case in which the parent directory is empty (i.e.
 *         we're writing the first dentry)
 *     (2) We can find a deleted dentry.
 *     (3) We have to append to the end of the directory (no deleted dentries)
 *
 * This one is a little long and a little nasty, but I've tried to make it
 * as clear as possible.
 */ 
static int fat_write_new_dentry(struct fat_dentry *dentry,
                                struct fat_diter *parent)
{
        struct fat_diter diter, next;
        int err;
        struct fat_dentry *d;

        diter.di_fs = parent->di_fs;

        fat_trace("%s: d_name=%s, parent_idx=%u", __func__, dentry->d_name,
                  fat_diter_get(parent)->d_idx);

        d = fat_diter_get(parent);
        err = fat_diter_begin(&diter, d);
        if (err) {
                if (err != -ENOENT)
                        return err;

                fat_trace("%s: case 1, empty parent dir", __func__);

                /* case (1): parent directory is empty */
                err = fat_alloc_cluster(FAT_END_MARK, diter.di_fs, &d->d_idx);
                d->d_fsize += FAT_CLUSTER_SIZE;
                if (err)
                        return err;
                err = fat_diter_begin(&diter, d);
                if (err)
                        return err;
                d = fat_diter_get(&diter);
                *d = *dentry;
                fat_dentry_set_flag(FAT_DF_LAST, d);
                err = fat_diter_commit(&diter);
                if (err)
                        goto out_free_diter;
                /*
                 * now that we've for sure written out a 'last' dentry in the
                 * new cluster, we can commit the parent with the new cluster
                 * index
                 */
                err = fat_diter_commit(parent);
                goto out_free_diter;
        }
        
        for (;;) {
                d = fat_diter_get(&diter);

                if (fat_dentry_is_del(d)) {
                        /* case (2): we found a deleted dentry */
                        fat_trace("%s: case 2, deleted dentry", __func__);
                        *d = *dentry;
                        err = fat_diter_commit(&diter);
                        goto out_free_diter;
                } else if (fat_dentry_is_last(d)) {
                        /*
                         * case (3): last dentry
                         *
                         * So we found the last dentry in a directory, but
                         * if the current cluster of dentries is full (call
                         * this case 3a we have to:
                         *   (1) allocate a cluster
                         *   (2) mark the new dentry as 'last' and commit it
                         *   (3) mark the old last dentry as 'not last' and
                         *       commit that.
                         *
                         * We need to do (3) after (2) so that if (2) fails,
                         * we don't end up with a directory with no 'last'
                         * dentry, which would be break everything. In this
                         * case if (2) succeeds but (3) fails, we end up with
                         * a leaked cluster instead, which is annoying
                         * but not catastophic. (however, we don't currently
                         * do anything to try and remedy the leaked cluster
                         * since it's so unlikely ...)
                         *
                         * If the cluster isn't full it's not too bad, we
                         * call this case 3b (the else case here)
                         */ 
                        if (diter.di_d_index == FAT_DENTRIES_PER_CLUSTER - 1) {
                                struct fat_dentry *slot;

                                fat_trace("%s: case 3a, full cluster",
                                          __func__);

                                /* 1: allocate a cluster */
                                err = fat_diter_alloc_cluster(&diter);
                                if (err)
                                        goto out_free_diter;
                                err = fat_diter_clone(&diter, &next);
                                if (err)
                                        goto out_free_diter;
                                /*
                                 * force the advance because we're walking
                                 * over the 'last' dentry, which normally
                                 * is an error
                                 */
                                err = fat_diter_advance_force(&next);
                                if (err)
                                        goto out_free_next;
                                slot = fat_diter_get(&next);
                                *slot = *dentry;

                                /* 2: mark the new dentry as last */
                                fat_dentry_set_flag(FAT_DF_LAST, slot);
                                err = fat_diter_commit(&next);
                                if (err)
                                        /* XXX: leaking a cluster here */
                                        goto out_free_next;

                                /*
                                 * 3: commit marking the old last dentry as
                                 * 'not last'
                                 */
                                fat_dentry_clear_flag(FAT_DF_LAST, d);
                                err = fat_diter_commit(&diter);
                                if (err)
                                        goto out_free_next;
                                d = fat_diter_get(parent);
                                d->d_fsize += FAT_CLUSTER_SIZE;
                                err = fat_diter_commit(parent);
                                goto out_free_next;
                        } else {
                                fat_trace("%s: case 3b, partial cluster",
                                          __func__);
                                
                                fat_dentry_clear_flag(FAT_DF_LAST, d);
                                err = fat_diter_advance(&diter);
                                /* should never error here */
                                assert(err == 0);
                                d = fat_diter_get(&diter);
                                *d = *dentry;
                                fat_dentry_set_flag(FAT_DF_LAST, d);
                                err = fat_diter_commit(&diter);
                                goto out_free_diter;
                        }
                } else {
                        err = fat_diter_advance(&diter);
                        if (err)
                                goto out_free_diter;
                }
        }

out_free_next:
        fat_diter_end(&next);
out_free_diter:
        fat_diter_end(&diter);
        if (err)
                fat_error("%s: %s", __func__, strerror(-err));
        else if (fat_dentry_is_dir(dentry)) {
                d = fat_diter_get(parent);
                d->d_nlink++;
                err = fat_diter_commit(parent);
        }
        return err;
}

/*
 * Given a path, get the path of the parent directory. Paths can
 * have trailing slashes, the parent directory name returned will
 * also have a trailing slash
 *
 * @path   the path
 *
 * @return the parent path. ***THIS MUST BE FREE'D***
 *
 * ex: path='/foo/bar/baz', returns '/foo/bar/'
 */ 
static char *fat_get_ppath(const char *path)
{
        char *ppath = strdup(path);
        if (ppath) {
                /* get the last non-null character in path */
                char *c = ppath + (strlen(ppath) - 1);

                /* eat a trailing slash, if there is one */
                if (*c == '/')
                        c--;

                /* eat the leaf path name */
                while (*c != '/')
                        c--;
                c++;

                /* write a null byte to end the string at the parent path */
                *c = '\0';
        }
        return ppath;
}

/* count the number of non-deleted dentries in a cluster */ 
static size_t fat_count_dentries(struct fat_cluster *cl)
{
        size_t count, i;
        for (count = 0, i = 0; i < FAT_DENTRIES_PER_CLUSTER; ++i) {
                struct fat_dentry *d = &cl->c_dentries[i];
                if (!fat_dentry_is_del(d))
                        count++;
                if (fat_dentry_is_last(d))
                        break;
        }
        return count;
}

/* merge two clusters into one and do the appropriate cleanup in the fat */
static int fat_merge_dir_clusters(struct fat_diter *target,
                                  struct fat_diter *victim)
{
        struct fat_cluster *tcl = target->di_cluster;
        struct fat_cluster *vcl = victim->di_cluster;
        uint32_t vidx = vcl->c_idx;
        struct fat_fs *fs = target->di_fs;
        int err;
        struct fat_cluster new;
        new.c_idx = tcl->c_idx;
        size_t new_idx = 0, i;

        fat_trace("%s: tcl->c_idx=%u, vcl->c_idx=%u, target has %zu dentries, victim has %zu dentries",
                  __func__, tcl->c_idx, vcl->c_idx,
                  fat_count_dentries(tcl), fat_count_dentries(vcl));

        memset(&new, 0, sizeof new);
        new.c_idx = tcl->c_idx;
        for (i = 0; i < FAT_DENTRIES_PER_CLUSTER; ++i) {
                struct fat_dentry *d = &tcl->c_dentries[i];
                bool was_last = fat_dentry_is_last(d);
                if (!fat_dentry_is_del(d)) {
                        fat_trace("%s: tcl[%zu]=\"%s\"", __func__, i, d->d_name);
                        fat_dentry_clear_flag(FAT_DF_LAST, d);
                        new.c_dentries[new_idx++] = *d;
                }
                if (was_last)
                        break;
        }
        for (i = 0; i < FAT_DENTRIES_PER_CLUSTER; ++i) {
                struct fat_dentry *d = &vcl->c_dentries[i];
                bool was_last = fat_dentry_is_last(d);
                if (!fat_dentry_is_del(d)) {
                        fat_trace("%s: vcl[%zu]=\"%s\"", __func__, i, d->d_name);
                        fat_dentry_clear_flag(FAT_DF_LAST, d);
                        new.c_dentries[new_idx++] = *d;
                }
                if (was_last)
                        break;
        }

        if (fat_follow_chain(vidx, fs) == FAT_END_MARK)
                fat_dentry_set_flag(FAT_DF_LAST, &new.c_dentries[--new_idx]);
        else
                while (new_idx < FAT_DENTRIES_PER_CLUSTER)
                        fat_dentry_set_flag(FAT_DF_DEL, &new.c_dentries[new_idx++]);
        memcpy(tcl, &new, sizeof new);
        err = fat_diter_commit(target);
        if (err)
                return err;

        for (i = 0; i < FAT_DENTRIES_PER_CLUSTER; ++i) {
                struct fat_dentry *d = &tcl->c_dentries[i];
                if (!fat_dentry_is_del(d))
                        fat_trace("%s: tcl[%zu]=\"%s\"", __func__, i, d->d_name);
                if (fat_dentry_is_last(d))
                        break;
        }

        /* remove the victim cluster from the cluster chain */
        fat_modify_fat(tcl->c_idx, fat_follow_chain(vidx, fs), fs);
        return fat_free_cluster(vidx, fs);
}

/*
 * delete a directory entry and propperly handle the parent's d_nlink count
 * and free clusters if possible
 */ 
static int fat_delete_dentry(struct fat_diter *diter, const char *path)
{
        int err;
        struct fat_fs *fs = diter->di_fs;
        struct fat_dentry *d = fat_diter_get(diter);
        struct fat_dentry *pd;
        struct fat_diter next, parent;
        char *ppath = NULL;
        uint32_t idx;

        /* mark the dentry as deleted */
        fat_dentry_set_flag(FAT_DF_DEL, d);
        err = fat_diter_commit(diter);
        if (err)
                return err;

        /* get the parent dentry */
        ppath = fat_get_ppath(path);
        if (!ppath)
                return -ENOMEM;
        err = fat_get_diter(ppath, fs, &parent);
        if (err)
                goto out_free_ppath;
        pd = fat_diter_get(&parent);

        /* merge adjacent clusters, if possible */
        err = fat_diter_clone(diter, &next);
        if (err)
                goto out_free_parent;
        err = fat_diter_advance_cluster(&next);
        if (err) {
                if (err != -ENOENT)
                        goto out_free_next;
                err = 0;
        } else {
                if (fat_count_dentries(next.di_cluster)
                    + fat_count_dentries(diter->di_cluster)
                    <= FAT_DENTRIES_PER_CLUSTER) {

                        fat_trace("%s: merging adjacent cluster", __func__);
                        
                        err = fat_merge_dir_clusters(diter, &next);
                        pd->d_fsize -= FAT_CLUSTER_SIZE;
                        err = fat_diter_commit(&parent);
                        if (err)
                                goto out_free_next;
                }
        }

        /* decriment d_nlink in parent, if necessary */
        if (fat_dentry_is_dir(d)) {

                fat_trace("%s: decrementing nlink in parent", __func__);
                
                pd->d_nlink--;
                err = fat_diter_commit(&parent);
                if (err)
                        goto out_free_next;
        }

        /* empty a directory if we're removing the last dentry */
        idx = diter->di_cluster->c_idx;
        if (pd->d_idx == idx && fs->f_fat[idx] == FAT_END_MARK
            && fat_count_dentries(diter->di_cluster) == 0) {

                fat_trace("%s: removing last dentry in directory", __func__);

                /* modify the parent dentry to point to nothing */
                pd->d_idx = FAT_END_MARK;
                assert(pd->d_fsize == FAT_CLUSTER_SIZE);
                pd->d_fsize = 0;
                err = fat_diter_commit(&parent);
                if (err)
                        goto out_free_ppath;

                /* free the corresponding cluster */
                err = fat_free_cluster(idx, fs);
        }
        
out_free_next:
        fat_diter_end(&next);
out_free_parent:
        fat_diter_end(&parent);
out_free_ppath:
        free(ppath);
        return err;
}

static int fat_getattr(const char *path, struct stat *stbuf)
{
        int err;
        struct fat_dentry d;

        err = fat_get_dentry(path, &global_fat_fs, &d);
        if (err)
                return err;

        memset(stbuf, 0, sizeof *stbuf);
        /* fake perms */
        stbuf->st_mode = S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
        stbuf->st_size = d.d_fsize;
        stbuf->st_nlink = d.d_nlink;
        if (fat_dentry_is_file(&d))
                stbuf->st_mode |= S_IFREG;
        else if (fat_dentry_is_dir(&d))
                stbuf->st_mode |= S_IFDIR;
        else if (fat_dentry_is_link(&d)) {
                stbuf->st_mode |= S_IFLNK;
                stbuf->st_mode |= S_IRWXU|S_IRWXG|S_IRWXO;
        } else
                fat_error("%s: unknown file type, flags=0x%xu", __func__,
                          d.d_flags);

        stbuf->st_blksize = FAT_BLOCK_SIZE;
        stbuf->st_blocks = (stbuf->st_size + FAT_BLOCK_SIZE - 1)/FAT_BLOCK_SIZE;
        return 0;
}

static int fat_access(const char *path, int mask)
{
        /* we don't implement perms */
        return 0;
}

static int fat_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
        int err;
        struct fat_diter diter;
        struct fat_dentry parent, *d;

        err = fat_get_dentry(path, &global_fat_fs, &parent);
        if (err)
                return err;

        filler(buf, ".", NULL, 0);
        filler(buf, "..", NULL, 0);

        diter.di_fs = &global_fat_fs;
        err = fat_diter_begin(&diter, &parent);
        if (err)
                return err == -ENOENT ? 0 : err;

        for (;;) {
                d = fat_diter_get(&diter);
                if (!fat_dentry_is_del(d))
                        filler(buf, d->d_name, NULL, 0);
                if (fat_dentry_is_last(d))
                        break;
                err = fat_diter_advance(&diter);
                if (err)
                        break;
        }

        fat_diter_end(&diter);
        return err;
}

static int __fat_truncate(struct fat_diter *diter, off_t size)
{
        struct fat_dentry *d;
        struct fat_fs *fs = &global_fat_fs;
        int err = 0;
        uint32_t idx;
        size_t allocd_size = 0;
        
        d = fat_diter_get(diter);
        if (!fat_dentry_is_file(d)) {
                err = -EISDIR;
                goto out_commit;
        }

        idx = d->d_idx;

        /* make the file smaller */
        if (size < d->d_fsize) {
                /* find the index of the first cluster we should free */
                uint32_t prev = 0;
                for (;;) {
                        /* do we need the current cluster? */
                        if (allocd_size >= (size_t)size) {
                                if (prev)
                                        fat_modify_fat(prev, FAT_END_MARK, fs);
                                break;
                        }
                        allocd_size += FAT_CLUSTER_SIZE;
                        prev = idx;
                        idx = fat_follow_chain(idx, fs);
                }
                
                fat_trace("%s: idx of first cluster to free=%u", __func__,
                          idx);
                
                /* free all subsequent clusters */
                while (idx != FAT_END_MARK) {
                        uint32_t next_idx = fat_follow_chain(idx, fs);
                        err = fat_free_cluster(idx, fs);
                        fat_trace("%s: err: %s", __func__, strerror(-err));
                        if (err)
                                goto out_commit;
                        idx = next_idx;
                }
        }
        /* make the file bigger */
        else {
                /* find the index of the last allocated cluster */
                if (d->d_fsize != 0)
                        for (;;) {
                                uint32_t next = fat_follow_chain(idx, fs);
                                allocd_size += FAT_CLUSTER_SIZE;
                                if (next == FAT_END_MARK)
                                        break;
                                idx = next;
                        }

                fat_trace("%s: index of last allocated cluster=%u", __func__,
                          idx);

                /* allocate more space */
                while (allocd_size < (size_t)size) {
                        if (idx == FAT_END_MARK) {
                                err = fat_alloc_cluster(FAT_END_MARK, fs,
                                                        &d->d_idx);
                                idx = d->d_idx;
                        } else
                                err = fat_alloc_cluster(idx, fs, &idx);
                        if (err)
                                goto out_commit;
                        allocd_size += FAT_CLUSTER_SIZE;
                }
        }

out_commit:
        if (size == 0)
                d->d_idx = FAT_END_MARK;
        d->d_fsize = size;
        return fat_diter_commit(diter);
}

static int fat_truncate(const char *path, off_t size)
{
        struct fat_diter diter;
        struct fat_fs *fs = &global_fat_fs;
        int err;

        fat_trace("%s: path=%s, size=%lu", __func__, path, size);

        err = fat_get_diter(path, fs, &diter);
        if (err)
                return err;
        err = __fat_truncate(&diter, size);
        fat_diter_end(&diter);
        return err;
}

static int fat_open(const char *path, struct fuse_file_info *fi)
{
        struct fat_dentry d;
        return fat_get_dentry(path, &global_fat_fs, &d);
}

static int fat_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
        struct fat_dentry d;
        int err;
        struct fat_fs *fs = &global_fat_fs;
        uint32_t idx;
        off_t cur_off = 0;
        struct fat_cluster cluster;
        size_t read = 0; /* number of bytes read so far */

        fat_trace("%s: path=%s, size=%zu, offset=%ld", __func__, path, size,
                  offset);
        
        err = fat_get_dentry(path, fs, &d);
        if (err)
                return err;
        if (!fat_dentry_is_file(&d))
                return -EINVAL; /* ????? */

        /* bail early for out of bounds reads */
        if (offset >= d.d_fsize)
                return 0;

        /* fix size early for past-the-end reads */
        if (offset + size > d.d_fsize)
                size = d.d_fsize - offset;

        idx = d.d_idx;
        while (cur_off < offset - offset%FAT_CLUSTER_SIZE) {
                idx = fat_follow_chain(idx, fs);
                cur_off += FAT_CLUSTER_SIZE;
        }
        cur_off = offset;

        cluster.c_idx = idx;
        for (read = 0; read < size; ) {
                size_t cls_start = cur_off%FAT_CLUSTER_SIZE;
                size_t bytes_to_copy = FAT_CLUSTER_SIZE - cls_start;

                /* last cluster */
                if (bytes_to_copy > size - read)
                        bytes_to_copy = size - read;

                err = fat_read_cluster(&cluster, fs);
                if (err)
                        return read ? read : err;
                memcpy(buf + read, cluster.c_fbuf + cls_start, bytes_to_copy);
                cur_off += bytes_to_copy;
                read += bytes_to_copy;
                cluster.c_idx = fat_follow_chain(cluster.c_idx, fs);
        }
        return read;
}

/* there's some henious code duplication between read and write but whatever */
static int fat_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
        struct fat_dentry d;
        int err;
        struct fat_fs *fs = &global_fat_fs;
        off_t cur_off = 0;
        struct fat_cluster cl;
        size_t written;
        uint32_t idx;

        fat_trace("%s: path=%s, size=%zu, offset=%ld", __func__, path, size,
                  offset);

        err = fat_get_dentry(path, fs, &d);
        if (err)
                return err;
        if (!fat_dentry_is_file(&d))
                return -EINVAL; /* xxx: better error */

        /* if this is an append, allocate clusters first */
        if (offset + size > d.d_fsize) {
                err = fat_truncate(path, offset + size);
                if (err)
                        return err;
        }

        /* re-read d since fat_truncate modified it */
        err = fat_get_dentry(path, fs, &d);
        if (err)
                return err;

        /* walk to offset */
        idx = d.d_idx;
        while (cur_off < offset - offset%FAT_CLUSTER_SIZE) {
                idx = fat_follow_chain(idx, fs);
                cur_off += FAT_CLUSTER_SIZE;
        }
        cur_off = offset;

        cl.c_idx = idx;
        for (written = 0; written < size; ) {
                size_t cls_start = cur_off%FAT_CLUSTER_SIZE;
                size_t bytes_to_copy = FAT_CLUSTER_SIZE - cls_start;

                /* last cluster */
                if (bytes_to_copy > size - written)
                        bytes_to_copy = size - written;

                err = fat_read_cluster(&cl, fs);
                if (err)
                        return written ? written : err;

                fat_trace("%s: c_idx=%u, bytes_to_copy=%zu, cls_start=%zu, cur_off=%lu",
                          __func__, cl.c_idx, bytes_to_copy, cls_start, cur_off);

                memcpy(cl.c_fbuf + cls_start, buf + written, bytes_to_copy);
                err = fat_write_cluster(&cl, fs);
                if (err)
                        return written ? written : err;

                cur_off += bytes_to_copy;
                written += bytes_to_copy;
                cl.c_idx = fat_follow_chain(cl.c_idx, fs);
        }
        return written;
}

static int fat_readlink(const char *path, char *buf, size_t size)
{
        struct fat_dentry d;
        int err;
        struct fat_fs *fs = &global_fat_fs;
        struct fat_cluster cl;

        fat_trace("%s: path=%s, size=%zu", __func__, path, size);

        err = fat_get_dentry(path, fs, &d);
        if (err)
                return err;
        if (!fat_dentry_is_link(&d))
                return -EINVAL; /* xxx: better err? */
        if (d.d_idx == FAT_END_MARK) {
                fat_error("%s: empty symlink", __func__);
                return -EIO;
        }

        cl.c_idx = d.d_idx;
        err = fat_read_cluster(&cl, fs);
        if (err)
                return err;
        if (size > d.d_fsize)
                size = d.d_fsize;
        else
                size--; /* make sure we have room for a null byte */
        strncpy(buf, (char*)cl.c_fbuf, size);
        buf[size] = '\0';
        return 0;
}

/* more henous code duplication between this and mkdir */
static int fat_mknod(const char *path, mode_t mode, dev_t rdev)
{
        struct fat_diter diter;
        struct fat_dentry d;
        struct fat_fs *fs = &global_fat_fs;
        char *ppath;
        const char *leaf;
        int err = -ENOTSUP;

        if ((mode & S_IFMT) != S_IFREG)
                return err;

        /* find the parent path and the name of the leaf */
        ppath = fat_get_ppath(path);
        if (!ppath)
                return -ENOMEM;
        leaf = path + strlen(ppath);
        if (strlen(leaf) >= sizeof d.d_name) {
                err = -EINVAL;
                goto out_free_ppath;
        }

        memset(&d, 0, sizeof d);
        strcpy(d.d_name, leaf);
        assert(d.d_name[sizeof d.d_name - 1] == '\0');
        fat_dentry_set_flag(FAT_DF_FILE, &d);
        d.d_idx = FAT_END_MARK;
        d.d_fsize = 0;
        d.d_nlink = 1;
               
        /* commit the new dentry */
        err = fat_get_diter(ppath, fs, &diter);
        if (err)
                return err;
        err = fat_write_new_dentry(&d, &diter);
        fat_diter_end(&diter);
out_free_ppath:
        free(ppath);
        return err;
}

static int fat_mkdir(const char *path, mode_t mode)
{
        int err;
        struct fat_diter diter;
        struct fat_dentry d;
        char *ppath;
        const char *leaf;

        fat_trace("%s: path=%s, mode=0x%x", __func__, path, mode);
        
        /* find the parent path and the name of the leaf */
        ppath = fat_get_ppath(path);
        if (!ppath)
                return -ENOMEM;
        leaf = path + strlen(ppath);
        if (strlen(leaf) >= sizeof d.d_name) {
                err = -EINVAL;
                goto out;
        }

        fat_trace("%s: ppath=%s, leaf=%s", __func__, ppath, leaf);

        /* fill in the dentry */
        memset(&d, 0, sizeof d);
        strcpy(d.d_name, leaf);
        assert(d.d_name[sizeof d.d_name - 1] == '\0');
        fat_dentry_set_flag(FAT_DF_DENTRY, &d);
        d.d_idx = FAT_END_MARK;
        d.d_fsize = 0;
        d.d_nlink = 2;

        /* commit the dentry */
        err = fat_get_diter(ppath, &global_fat_fs, &diter);
        if (err)
                goto out;
        err = fat_write_new_dentry(&d, &diter);
        fat_diter_end(&diter);
out:
        free(ppath);
        return err;
}

static int fat_unlink(const char *path)
{
        struct fat_diter diter;
        struct fat_dentry *d;
        int err;
        struct fat_fs *fs = &global_fat_fs;

        fat_trace("%s: path=%s", __func__, path);

        err = fat_get_diter(path, fs, &diter);
        if (err)
                return err;

        /* clean up any clusters allocated to the dentry */
        d = fat_diter_get(&diter);
        if (fat_dentry_is_file(d))
                err = __fat_truncate(&diter, 0);
        else if (fat_dentry_is_link(d))
                err = fat_free_cluster(d->d_idx, fs);
        else
                err = -EISDIR;

        if (err)
                goto out;

        /* remove the dentry */
        err = fat_delete_dentry(&diter, path);
        if (err)
                goto out;

out:
        fat_diter_end(&diter);
        return err;
}

static int fat_rmdir(const char *path)
{
        struct fat_diter diter;
        struct fat_dentry *d;
        int err;
        struct fat_fs *fs = &global_fat_fs;

        fat_trace("%s: path=%s", __func__, path);

        err = fat_get_diter(path, fs, &diter);
        if (err)
                return err;
        d = fat_diter_get(&diter);
        if (!fat_dentry_is_dir(d)) {
                fat_diter_end(&diter);
                return -ENOTDIR;
        }
        if (d->d_fsize != 0) {
                fat_diter_end(&diter);
                return -ENOTEMPTY;
        }
        err = fat_delete_dentry(&diter, path);
        fat_diter_end(&diter);
        return err;
}

static int fat_symlink(const char *to, const char *from)
{
        struct fat_diter diter;
        struct fat_dentry d;
        struct fat_fs *fs = &global_fat_fs;
        int err;
        char *ppath;
        const char *leaf;
        struct fat_cluster cl;
        size_t to_len = strlen(to);

        fat_trace("%s: to=%s, from=%s", __func__, to, from);

        if (to_len > FAT_CLUSTER_SIZE)
                return -ENAMETOOLONG;
        
        /* find the parent path and the name of the leaf */
        ppath = fat_get_ppath(from);
        if (!ppath)
                return -ENOMEM;
        leaf = from + strlen(ppath);
        if (strlen(leaf) >= sizeof d.d_name) {
                err = -EINVAL;
                goto out;
        }

        fat_trace("%s: ppath=%s, leaf=%s", __func__, ppath, leaf);

        /* fill in the dentry */
        memset(&d, 0, sizeof d);
        strcpy(d.d_name, leaf);
        assert(d.d_name[sizeof d.d_name - 1] == '\0');
        fat_dentry_set_flag(FAT_DF_LINK, &d);
        d.d_fsize = to_len;
        d.d_nlink = 1;

        /* allocate a cluster for the symlink body */
        err = fat_alloc_cluster(FAT_END_MARK, fs, &d.d_idx);
        if (err)
                goto out;

        /* write out the simlink body */
        memset(&cl, 0, sizeof cl);
        memcpy(cl.c_fbuf, to, to_len);
        cl.c_idx = d.d_idx;
        err = fat_write_cluster(&cl, fs);
        if (err)
                goto out;

        /* commit the dentry */
        err = fat_get_diter(ppath, &global_fat_fs, &diter);
        if (err)
                goto out;
        err = fat_write_new_dentry(&d, &diter);
        fat_diter_end(&diter);
out:
        free(ppath);
        return 0;
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
        struct fat_fs *fs = &global_fat_fs;
        size_t blks_per_cls = FAT_CLUSTER_SIZE/FAT_BLOCK_SIZE;

        (void)path;

        memset(stbuf, 0, sizeof *stbuf);
        stbuf->f_bsize = FAT_BLOCK_SIZE;
        stbuf->f_blocks = fs->f_sb->s_fat_entries*blks_per_cls;
        stbuf->f_bfree = fs->f_sb->s_free*blks_per_cls;
        stbuf->f_bfree = fs->f_sb->s_free*blks_per_cls;
        stbuf->f_namemax = FAT_NAME_LEN;

        return 0;
}

static int fat_release(const char *path, struct fuse_file_info *fi)
{
        (void)path;
        return 0;
}

static int fat_fgetattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi)
{
        (void)fi;
        return fat_getattr(path, stbuf);
}

static int fat_create(const char *path, mode_t mode,
                      struct fuse_file_info *fi)
{
        (void)fi;
        return fat_mknod(path, mode, 0);
}

static struct fuse_operations fat_oper = {
	.getattr        = fat_getattr,
        .fgetattr       = fat_fgetattr,
	.access		= fat_access,
	.readlink	= fat_readlink,
	.readdir	= fat_readdir,
        .create         = fat_create,
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
        .release        = fat_release,
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
