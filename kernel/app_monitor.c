#include <linux/app_monitor.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>

#define MAX_MONITORED_PIDS 100
#define MAX_APP_NAME_LEN 32
#define CONFIG_FILE_PATH "/data/app_monitor.conf"

/* 监控的进程组ID列表 */
static pid_t monitored_tgids[MAX_MONITORED_PIDS];
static int monitored_count = 0;
static DEFINE_SPINLOCK(monitor_lock);

/* 静态目标应用名称列表 */
static char target_apps[10][MAX_APP_NAME_LEN] = {
    "cn.damai",
    "com.taobao.taobao", 
    "com.tmall.wireless",
    "com.alibaba.android.rimet",
    "com.tencent.mm",
    "com.tencent.mobileqq",
    "com.eg.android.AlipayGphone",
    "com.sina.weibo",
    "",  /* 结束标记 */
    ""
};

/* 全局监控开关 */
static bool monitor_all_enabled = false;

/**
 * 检查进程名是否为目标应用
 */
bool app_monitor_is_target(const char *old_comm, const char *new_comm)
{
    int i;
    
    if (!new_comm)
        return false;
    
    /* 检查静态应用列表 */
    for (i = 0; i < 10 && target_apps[i][0] != '\0'; i++) {
        if (strstr(new_comm, target_apps[i]) != NULL) {
            return true;
        }
    }
    
    return false;
}

/**
 * 检查当前进程是否在监控的进程组中
 */
bool app_monitor_is_monitored_process_group(void)
{
    unsigned long flags;
    int i;
    pid_t current_tgid;
    bool found = false;
    
    if (!current)
        return false;
        
    current_tgid = current->tgid;
    
    spin_lock_irqsave(&monitor_lock, flags);
    for (i = 0; i < monitored_count; i++) {
        if (monitored_tgids[i] == current_tgid) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&monitor_lock, flags);
    
    return found;
}

/**
 * 添加进程组到监控列表
 */
void app_monitor_add_process_group(pid_t tgid)
{
    unsigned long flags;
    int i;
    
    if (tgid <= 0)
        return;
    
    spin_lock_irqsave(&monitor_lock, flags);
    
    /* 检查是否已存在 */
    for (i = 0; i < monitored_count; i++) {
        if (monitored_tgids[i] == tgid) {
            spin_unlock_irqrestore(&monitor_lock, flags);
            return;
        }
    }
    
    /* 添加新的进程组 */
    if (monitored_count < MAX_MONITORED_PIDS) {
        monitored_tgids[monitored_count] = tgid;
        monitored_count++;
        printk(KERN_INFO "APP_MONITOR: Added process group TGID=%d, total=%d\n", 
               tgid, monitored_count);
    } else {
        printk(KERN_WARNING "APP_MONITOR: Cannot add TGID=%d, list full\n", tgid);
    }
    
    spin_unlock_irqrestore(&monitor_lock, flags);
}

/**
 * 从监控列表中移除进程组
 */
void app_monitor_remove_process_group(pid_t tgid)
{
    unsigned long flags;
    int i, j;
    
    spin_lock_irqsave(&monitor_lock, flags);
    for (i = 0; i < monitored_count; i++) {
        if (monitored_tgids[i] == tgid) {
            /* 移除并压缩数组 */
            for (j = i; j < monitored_count - 1; j++) {
                monitored_tgids[j] = monitored_tgids[j + 1];
            }
            monitored_count--;
            printk(KERN_INFO "APP_MONITOR: Removed process group TGID=%d, total=%d\n", 
                   tgid, monitored_count);
            break;
        }
    }
    spin_unlock_irqrestore(&monitor_lock, flags);
}

/**
 * 检查是否启用全局监控
 */
bool app_monitor_is_enabled_all(void)
{
    return monitor_all_enabled;
}

/* ========== 兼容函数 ========== */

/**
 * 兼容函数：检查PID是否被监控
 */
bool app_monitor_is_monitored_pid(pid_t pid)
{
    /* 如果启用全局监控，直接返回true */
    if (monitor_all_enabled)
        return true;
        
    /* 否则检查进程组 */
    return app_monitor_is_monitored_process_group();
}

/**
 * 兼容函数：添加PID（实际添加进程组）
 */
void app_monitor_add_pid(pid_t pid)
{
    /* 将PID作为TGID添加到进程组监控 */
    app_monitor_add_process_group(pid);
}

/**
 * 兼容函数：移除PID（实际移除进程组）
 */
void app_monitor_remove_pid(pid_t pid)
{
    /* 移除对应的进程组 */
    app_monitor_remove_process_group(pid);
}