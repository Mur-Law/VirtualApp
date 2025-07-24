#include <linux/app_monitor.h>

long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
    struct filename *tmp;
    int fd;

    /* 应用监控：记录文件打开操作 */
    if (app_monitor_is_monitored_pid(current->pid) || app_monitor_is_enabled_all()) {
        char *user_path;
        long copied;
        const char *dfd_info = (dfd == AT_FDCWD) ? "CWD" : "FD";
        
        user_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (user_path) {
            copied = strncpy_from_user(user_path, filename, PATH_MAX - 1);
            if (copied > 0) {
                user_path[copied] = '\0';
                printk(KERN_INFO "hh7_OPEN: pid=%d tgid=%d comm=%s dfd=%s file=%s flags=0x%x mode=0x%x\n",
                       current->pid, current->tgid, current->comm, dfd_info, user_path, flags, mode);
            }
            kfree(user_path);
        }
    }

    tmp = getname(filename);
    if (IS_ERR(tmp))
        return PTR_ERR(tmp);

    fd = get_unused_fd_flags(flags);
    if (fd >= 0) {
        struct file *f = do_filp_open(dfd, tmp, &op);
        if (IS_ERR(f)) {
            put_unused_fd(fd);
            fd = PTR_ERR(f);
        } else {
            fsnotify_open(f);
            fd_install(fd, f);
        }
    }
    putname(tmp);
    return fd;
}

/* 在 SYSCALL_DEFINE3(faccessat, ...) 中添加监控 */
SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
{
    /* 应用监控：记录文件访问权限检查 */
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
                printk(KERN_INFO "hh7_FACCESSAT: pid=%d tgid=%d comm=%s dfd=%s path=%s mode=%s(0x%x)\n",
                       current->pid, current->tgid, current->comm, dfd_info, user_path, mode_str, mode);
            }
            kfree(user_path);
        }
    }

    return do_faccessat(dfd, filename, mode);
}