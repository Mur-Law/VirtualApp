#include <linux/app_monitor.h>

case PR_SET_NAME:
{
    char comm[sizeof(me->comm)];
    
    comm[sizeof(me->comm) - 1] = 0;
    if (strncpy_from_user(comm, (char __user *)arg2,
                          sizeof(me->comm) - 1) < 0)
        return -EFAULT;
    
    /* 应用监控：检查是否是目标应用的主进程 */
    if (app_monitor_is_target(me->comm, comm)) {
        printk(KERN_INFO "TARGET_APP_MAIN: pid=%d tgid=%d old=%s new=%s\n",
               me->pid, me->tgid, me->comm, comm);
        
        /* 将进程组添加到监控列表 */
        app_monitor_add_process_group(me->tgid);
    }
    /* 监控已有进程组的线程命名 */
    else if (app_monitor_is_monitored_process_group()) {
        printk(KERN_INFO "TARGET_APP_THREAD: pid=%d tgid=%d old=%s new=%s\n",
               me->pid, me->tgid, me->comm, comm);
    }
    /* 全局监控模式 */
    else if (app_monitor_is_enabled_all()) {
        printk(KERN_INFO "ALL_APP_PRCTL: pid=%d tgid=%d old=%s new=%s\n",
               me->pid, me->tgid, me->comm, comm);
    }
    
    set_task_comm(me, comm);
    proc_comm_connector(me);
    break;
}