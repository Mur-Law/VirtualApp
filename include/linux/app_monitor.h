#ifndef _LINUX_APP_MONITOR_H
#define _LINUX_APP_MONITOR_H

#include <linux/types.h>

/* 应用监控核心函数 */
bool app_monitor_is_target(const char *old_comm, const char *new_comm);
bool app_monitor_is_monitored_process_group(void);
void app_monitor_add_process_group(pid_t tgid);
void app_monitor_remove_process_group(pid_t tgid);

/* 兼容函数 - 保持与旧代码兼容 */
bool app_monitor_is_monitored_pid(pid_t pid);
void app_monitor_add_pid(pid_t pid);
void app_monitor_remove_pid(pid_t pid);

/* 扩展功能 */
bool app_monitor_is_enabled_all(void);

#endif /* _LINUX_APP_MONITOR_H */