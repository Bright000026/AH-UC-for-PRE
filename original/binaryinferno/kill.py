import subprocess
import os
import signal

# 使用subprocess.check_output执行pgrep命令查找相关进程
# 注意：这里假设你有足够的权限来执行此操作
def kill_parallel():
    cmd = "pgrep -af /usr/bin/parallel"
    output = subprocess.check_output(cmd, shell=True, text=True)
    process_ids = output.strip().split(' ')

    # 过滤掉空白行
    process_ids = [pid for pid in process_ids if pid]

    print(f"parallel process ID: {process_ids}")

    # 遍历进程ID并尝试杀死它们
    #for pid in process_ids:
    try:
        os.kill(int(process_ids[0]),signal.SIGTERM)#, signal.SIGTERM)  # 使用SIGTERM信号尝试优雅地终止进程
        os.kill(int(process_ids[0]),signal.SIGTERM)
    except ProcessLookupError:
        return 
    print(f"sent kill signal to {process_ids[0]}")
