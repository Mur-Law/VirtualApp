#include <linux/app_monitor.h>

int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flag)
{
    struct path path;
    int error = -EINVAL;
    unsigned int lookup_flags = 0;

    /* 应用监控：记录文件状态查询 */
    if (app_monitor_is_monitored_pid(current->pid) || app_monitor_is_enabled_all()) {
        char *user_path;
        long copied;
        const char *dfd_info = (dfd == AT_FDCWD) ? "CWD" : "FD";
        
        user_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (user_path) {
            copied = strncpy_from_user(user_path, filename, PATH_MAX - 1);
            if (copied > 0) {
                user_path[copied] = '\0';
                printk(KERN_INFO "hh7_FSTATAT: pid=%d tgid=%d comm=%s dfd=%s path=%s flags=0x%x\n",
                       current->pid, current->tgid, current->comm, dfd_info, user_path, flag);
            }
            kfree(user_path);
        }
    }

    if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |
                  AT_EMPTY_PATH)) != 0)
        return -EINVAL;

    if (!(flag & AT_SYMLINK_NOFOLLOW))
        lookup_flags |= LOOKUP_FOLLOW;
    if (flag & AT_EMPTY_PATH)
        lookup_flags |= LOOKUP_EMPTY;
    if (flag & AT_NO_AUTOMOUNT)
        lookup_flags |= LOOKUP_NO_AUTOMOUNT;

retry:
    error = user_path_at(dfd, filename, lookup_flags, &path);
    if (error)
        goto out;

    error = vfs_getattr(&path, stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
    path_put(&path);
    if (retry_estale(error, lookup_flags)) {
        lookup_flags |= LOOKUP_REVAL;
        goto retry;
    }
out:
    return error;
}

int vfs_fstat(unsigned int fd, struct kstat *stat)
{
    struct fd f;
    int error = -EBADF;

    /* 应用监控：记录文件描述符状态查询 */
    if (app_monitor_is_monitored_pid(current->pid) || app_monitor_is_enabled_all()) {
        const char *safe_path = "<unknown>";
        
        f = fdget_raw(fd);
        if (f.file && f.file->f_path.dentry && f.file->f_path.dentry->d_name.name) {
            safe_path = f.file->f_path.dentry->d_name.name;
        }
        
        printk(KERN_INFO "hh7_FSTAT: pid=%d tgid=%d comm=%s fd=%d file=%s\n",
               current->pid, current->tgid, current->comm, fd, safe_path);
               
        if (f.file)
            fdput(f);
    }

    f = fdget_raw(fd);
    if (f.file) {
        error = vfs_getattr(&f.file->f_path, stat,
                            STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
        fdput(f);
    }
    return error;
}

SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
                struct stat __user *, statbuf, int, flag)
{
    struct kstat stat;
    int error;

    /* 应用监控：记录newfstatat调用 */
    if (app_monitor_is_monitored_pid(current->pid) || app_monitor_is_enabled_all()) {
        char *user_path;
        long copied;
        const char *dfd_info = (dfd == AT_FDCWD) ? "CWD" : "FD";
        
        user_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (user_path) {
            copied = strncpy_from_user(user_path, filename, PATH_MAX - 1);
            if (copied > 0) {
                user_path[copied] = '\0';
                printk(KERN_INFO "hh7_NEWFSTATAT: pid=%d tgid=%d comm=%s dfd=%s path=%s flags=0x%x\n",
                       current->pid, current->tgid, current->comm, dfd_info, user_path, flag);
            }
            kfree(user_path);
        }
    }

    error = vfs_fstatat(dfd, filename, &stat, flag);
    if (error)
        return error;
    return cp_new_stat(&stat, statbuf);
}

SYSCALL_DEFINE4(faccessat2, int, dfd, const char __user *, filename, int, mode, int, flags)
{
    /* 应用监控：记录faccessat2调用 */
    if (app_monitor_is_monitored_pid(current->pid) || app_monitor_is_enabled_all()) {
        char *user_path;
        long copied;
        const char *dfd_info = (dfd == AT_FDCWD) ? "CWD" : "FD";
        const char *mode_str;
        
        /* 解析访问模式 */
        switch (mode) {
            case F_OK: mode_str = "EXISTS"; break;
            case R_OK: mode_str = "READ"; break;
            case W_OK: mode_str = "WRITE"; break;
            case X_OK: mode_str = "EXEC"; break;
            case R_OK|W_OK: mode_str = "RW"; break;
            case R_OK|X_OK: mode_str = "RX"; break;
            case W_OK|X_OK: mode_str = "WX"; break;
            case R_OK|W_OK|X_OK: mode_str = "RWX"; break;
            default: mode_str = "UNKNOWN"; break;
        }
        
        user_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (user_path) {
            copied = strncpy_from_user(user_path, filename, PATH_MAX - 1);
            if (copied > 0) {
                user_path[copied] = '\0';
                printk(KERN_INFO "hh7_FACCESSAT2: pid=%d tgid=%d comm=%s dfd=%s path=%s mode=%s(0x%x) flags=0x%x\n",
                       current->pid, current->tgid, current->comm, dfd_info, user_path, mode_str, mode, flags);
            }
            kfree(user_path);
        }
    }

    return do_faccessat(dfd, filename, mode, flags);
}