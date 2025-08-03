#!/usr/bin/python3
from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output);  // 定义Perf事件映射，用于向用户空间传递数据
 
struct data_t {     
   int pid;
   int uid;
   char command[16];
   char message[12];
};
 
int hello(void *ctx) {
   struct data_t data = {}; 
   char message[12] = "Hello World";
 
   // 获取当前进程PID（高32位）和UID（低32位）
   data.pid = bpf_get_current_pid_tgid() >> 32; // 进程 ID
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; // 用户 ID 
   
   // 获取执行 execve 系统调用的进程中正在运行的可执行文件（或“命令”）的名称
   bpf_get_current_comm(&data.command, sizeof(data.command));

   // 安全读取内核数据到结构体
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
 
   // 提交数据到Perf缓冲区
   // ctx 参数是内核自动传递给 eBPF 处理函数的执行上下文
   output.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")


def print_event(cpu, data, size):
    data = b["output"].event(data)
    if data.pid % 2 == 0:
        print(
            f"pid 偶数{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}"
        )
    else:
        print(
            f"pid 奇数{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}"
        )


# 打开Perf缓冲区并设置回调
b["output"].open_perf_buffer(print_event)
while True:
    # 阻塞等待事件触发
    b.perf_buffer_poll()
