"""
修改 hello-map.py，使 eBPF 代码由多个系统调用触发。
例如， openat() 常用于打开文件，write() 用于向文件写入数据。
您可以先将 hello eBPF 程序附加到多个系统调用 kprobes。
然后尝试为不同的系统调用修改 eBPF 程序 hello 的版本，
证明您可以从多个不同的程序访问同一个映射。
"""
#!/usr/bin/python3
from bcc import BPF
from time import sleep

program = r"""
#include <uapi/linux/ptrace.h>

// 定义 UID 和 系统调用号
struct key_t{
   u32 uid;
   u32 syscall_id;
};

BPF_HASH(counter_table, struct key_t, u64); // BPF_HASH() 是一个 BCC 宏，用于定义一个哈希表映射。

static void update_counter(u32 syscall_id) {
   struct key_t key = {};
   key.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   key.syscall_id = syscall_id;

   u64 *counter = counter_table.lookup(&key);
   u64 new_count = 1;
   if(counter){
      new_count = *counter + 1;
   }

   counter_table.update(&key, &new_count);
}

// 为每个系统调用定义独立的处理函数
int hello_execve(struct pt_regs *ctx) {
    update_counter(59); // execve 的系统调用号 (x86_64)
    return 0;
}

int hello_openat(struct pt_regs *ctx) {
    update_counter(257); // openat 的系统调用号 (x86_64)
    return 0;
}

int hello_write(struct pt_regs *ctx) {
    update_counter(1); // write 的系统调用号 (x86_64)
    return 0;
}

"""

b = BPF(text=program)

syscall_execve = b.get_syscall_fnname("execve")
syscall_openat = b.get_syscall_fnname("openat")
syscall_write = b.get_syscall_fnname("write")

b.attach_kprobe(event=syscall_execve, fn_name="hello_execve")
b.attach_kprobe(event=syscall_openat, fn_name="hello_openat")
b.attach_kprobe(event=syscall_write, fn_name="hello_write")

print("Tracing multiple syscalls... Ctrl+C to exit")

try:
    while True:
        sleep(2)
        s = "\n"

        # 遍历哈希表并打印结果
        for k, v in b["counter_table"].items():
            syscall_name = {59: "EXECVE", 257: "OPENAT", 1: "WRITE"}.get(
                k.syscall_id, "UNKNOWN"
            )

            s += f"UID {k.uid}, Syscall {syscall_name} ({k.syscall_id}): {v.value}\n"

        print(s)
        b["counter_table"].clear()  # 清空映射以便观察新事件

except KeyboardInterrupt:
    print("Exiting...")
