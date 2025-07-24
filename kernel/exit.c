#include <linux/app_monitor.h>

void __noreturn do_exit(long code)
{
    struct task_struct *tsk = current;
    int group_dead;

    /* 应用监控：处理进程退出 */
    if (app_monitor_is_monitored_pid(current->pid)) {
        if (current->pid == current->tgid) {
            /* 主进程退出，清理整个监控条目 */
            printk(KERN_INFO "APP_MAIN_EXIT: pid=%d tgid=%d comm=%s exit_code=%ld\n",
                   current->pid, current->tgid, current->comm, code);
            app_monitor_remove_process_group(current->tgid);
        } else {
            /* 子线程退出，只记录 */
            printk(KERN_INFO "APP_THREAD_EXIT: pid=%d tgid=%d comm=%s exit_code=%ld\n",
                   current->pid, current->tgid, current->comm, code);
        }
    }

    profile_task_exit(tsk);
    kcov_task_exit(tsk);

    WARN_ON(blk_needs_flush_plug(tsk));

    if (unlikely(in_interrupt()))
        panic("Aiee, killing interrupt handler!");
    if (unlikely(!tsk->pid))
        panic("Attempted to kill the idle task!");

    /*
     * If do_exit is called because this processes oopsed, it's possible
     * that get_fs() was left as KERNEL_DS, so reset it to USER_DS before
     * continuing. Amongst other possible reasons, this is to prevent
     * mm_release()->clear_child_tid() from writing to a user-controlled
     * kernel address.
     */
    set_fs(USER_DS);

    ptrace_event(PTRACE_EVENT_EXIT, code);

    validate_creds_for_do_exit(tsk);

    /*
     * We're taking recursive faults here in do_exit. Safest is to just
     * leave this task alone and wait for reboot.
     */
    if (unlikely(tsk->flags & PF_EXITING)) {
        pr_alert("Fixing recursive fault but reboot is needed!\n");
        /*
         * We can do this unlocked here. The futex code uses
         * this flag just to verify whether the pi state
         * cleanup has been done or not. In the worst case it
         * loops once more. We pretend that the cleanup was
         * done as there is no way to return. Either the
         * OWNER_DIED bit is set by now or we push the blocked
         * task into the wait for ever nirwana as well.
         */
        tsk->flags |= PF_EXITPIDONE;
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule();
    }

    exit_signals(tsk);  /* sets PF_EXITING */

    /* sync mm's RSS info before statistics gathering */
    if (tsk->mm)
        sync_mm_rss(tsk->mm);
    acct_collect(code, group_dead);
    if (group_dead)
        tty_audit_exit();
    audit_free(tsk);

    tsk->exit_code = code;
    taskstats_exit(tsk, group_dead);

    exit_mm(tsk);

    if (group_dead)
        acct_process();
    trace_sched_process_exit(tsk);

    exit_sem(tsk);
    exit_shm(tsk);
    exit_files(tsk);
    exit_fs(tsk);
    if (group_dead)
        disassociate_ctty(1);
    exit_task_namespaces(tsk);
    exit_task_work(tsk);
    exit_thread(tsk);

    /*
     * Flush inherited counters to the parent - before the parent
     * gets woken up by child-exit notifications.
     *
     * because of cgroup mode, must be called before cgroup_exit()
     */
    perf_event_exit_task(tsk);

    sched_autogroup_exit_task(tsk);
    cgroup_exit(tsk);

    /*
     * FIXME: do that only when needed, using sched_exit tracepoint
     */
    flush_ptrace_hw_breakpoint(tsk);

    exit_notify(tsk, group_dead);
    proc_exit_connector(tsk);
    mpol_put_task_policy(tsk);
#ifdef CONFIG_FUTEX
    if (unlikely(current->pi_state_cache))
        kfree(current->pi_state_cache);
#endif
    /*
     * Make sure we are holding no locks:
     */
    debug_check_no_locks_held();
    /*
     * We can do this unlocked here. The futex code uses this flag
     * just to verify whether the pi state cleanup has been done
     * or not. In the worst case it loops once more.
     */
    tsk->flags |= PF_EXITPIDONE;

    if (tsk->io_context)
        exit_io_context(tsk);

    if (tsk->splice_pipe)
        free_pipe_info(tsk->splice_pipe);

    if (tsk->task_frag.page)
        put_page(tsk->task_frag.page);

    validate_creds_for_do_exit(tsk);

    check_stack_usage();
    preempt_disable();
    if (tsk->nr_dirtied)
        __this_cpu_add(dirty_throttle_leaks, tsk->nr_dirtied);
    exit_rcu();
    exit_tasks_rcu_start();

    /*
     * The setting of TASK_RUNNING by try_to_wake_up() may be delayed
     * when the following two conditions become true.
     *   - There is race condition of mmap_sem (It is acquired by
     *     exit_mm()), and
     *   - SMI occurs before setting TASK_RUNINNG.
     *     (or hypervisor of virtual machine switches to other guest)
     *  As a result, we may become TASK_RUNNING after becoming TASK_DEAD
     *
     * To avoid it, we have to wait for releasing tsk->pi_lock which
     * is held by try_to_wake_up()
     */
    raw_spin_unlock_wait(&tsk->pi_lock);

    /* causes final put_task_struct in finish_task_switch(). */
    tsk->state = TASK_DEAD;
    tsk->flags |= PF_NOFREEZE;	/* tell freezer to ignore us */
    schedule();
    BUG();
    /* Avoid "noreturn function does return".  */
    for (;;)
        cpu_relax();	/* For when BUG is null */
}