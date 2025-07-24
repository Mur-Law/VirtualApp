#include <linux/app_monitor.h>

static int do_execveat_common(int fd, struct filename *filename,
                             struct user_arg_ptr argv,
                             struct user_arg_ptr envp,
                             int flags)
{
    char *pathbuf = NULL;
    struct linux_binprm *bprm;
    struct file *file;
    struct files_struct *displaced;
    int retval;

    /* 应用监控：记录进程执行（早期检测） */
    if (app_monitor_is_monitored_pid(current->pid) || app_monitor_is_enabled_all()) {
        const char *exec_path = (filename && filename->name) ? filename->name : "<null>";
        printk(KERN_INFO "hh7_EXEC: pid=%d tgid=%d comm=%s file=%s flags=0x%x\n",
               current->pid, current->tgid, current->comm, exec_path, flags);
    }

    if (IS_ERR(filename))
        return PTR_ERR(filename);

    /*
     * We move the actual failure in case of RLIMIT_NPROC excess from
     * set*uid() to execve() because too many poorly written programs
     * don't check setuid() return code.  Here we additionally recheck
     * whether NPROC limit is still exceeded.
     */
    if ((current->flags & PF_NPROC_EXCEEDED) &&
        atomic_read(&current_user()->processes) > rlimit(RLIMIT_NPROC)) {
        retval = -EAGAIN;
        goto out_ret;
    }

    /* We're below the limit (still or again), so we don't want to make
     * further execve() calls fail. */
    current->flags &= ~PF_NPROC_EXCEEDED;

    retval = unshare_files(&displaced);
    if (retval)
        goto out_ret;

    retval = -ENOMEM;
    bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
    if (!bprm)
        goto out_files;

    retval = prepare_bprm_creds(bprm);
    if (retval)
        goto out_free;

    check_unsafe_exec(bprm);
    current->in_execve = 1;

    file = do_open_execat(fd, filename, flags);
    retval = PTR_ERR(file);
    if (IS_ERR(file))
        goto out_unmark;

    sched_exec();

    bprm->file = file;
    if (fd == AT_FDCWD || filename->name[0] == '/') {
        bprm->filename = filename->name;
    } else {
        if (filename->name[0] == '\0')
            pathbuf = kasprintf(GFP_KERNEL, "/dev/fd/%d", fd);
        else
            pathbuf = kasprintf(GFP_KERNEL, "/dev/fd/%d/%s",
                                fd, filename->name);
        if (!pathbuf) {
            retval = -ENOMEM;
            goto out_unmark;
        }
        /*
         * Record that a name derived from an O_CLOEXEC fd will be
         * inaccessible after exec. Relies on having exclusive access to
         * current->files (due to unshare_files above).
         */
        if (close_on_exec(fd, rcu_dereference_raw(current->files->fdt)))
            bprm->interp_flags |= BINPRM_FLAGS_PATH_INACCESSIBLE;
        bprm->filename = pathbuf;
    }
    bprm->interp = bprm->filename;

    retval = bprm_mm_init(bprm);
    if (retval)
        goto out_unmark;

    bprm->argc = count(argv, MAX_ARG_STRINGS);
    if ((retval = bprm->argc) < 0)
        goto out;

    bprm->envc = count(envp, MAX_ARG_STRINGS);
    if ((retval = bprm->envc) < 0)
        goto out;

    retval = prepare_binprm(bprm);
    if (retval < 0)
        goto out;

    retval = copy_strings_kernel(1, &bprm->filename, bprm);
    if (retval < 0)
        goto out;

    bprm->exec = bprm->p;
    retval = copy_strings(bprm->envc, envp, bprm);
    if (retval < 0)
        goto out;

    retval = copy_strings(bprm->argc, argv, bprm);
    if (retval < 0)
        goto out;

    retval = exec_binprm(bprm);
    if (retval < 0)
        goto out;

    /* execve succeeded */
    current->fs->in_exec = 0;
    current->in_execve = 0;
    acct_update_integrals(current);
    task_numa_free(current);
    free_bprm(bprm);
    kfree(pathbuf);
    if (displaced)
        put_files_struct(displaced);
    return retval;

out:
    if (bprm->mm) {
        acct_arg_size(bprm, 0);
        mmput(bprm->mm);
    }

out_unmark:
    current->fs->in_exec = 0;
    current->in_execve = 0;

out_free:
    free_bprm(bprm);
    kfree(pathbuf);

out_files:
    if (displaced)
        reset_files_struct(displaced);
out_ret:
    return retval;
}

/* 系统调用包装函数 */
SYSCALL_DEFINE5(execveat, int, fd, const char __user *, filename,
                const char __user *const __user *, argv,
                const char __user *const __user *, envp, int, flags)
{
    struct filename *path = getname_flags(filename, lookup_flags, NULL);
    int error = PTR_ERR(path);
    if (!IS_ERR(path)) {
        error = do_execveat_common(fd, path, argv, envp, flags);
        putname(path);
    }
    return error;
}

SYSCALL_DEFINE3(execve, const char __user *, filename,
                const char __user *const __user *, argv,
                const char __user *const __user *, envp)
{
    return do_execveat(AT_FDCWD, filename, argv, envp, 0);
}