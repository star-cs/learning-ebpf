'''
任何系统调用被调用时，都会触发该跟踪点。
修改 hello-map.py ，通过将其附加到相同的 sys_enter 原始跟踪点，
展示每个用户 ID 发出的总系统调用的数量。
'''
#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table); // BPF_HASH() 是一个 BCC 宏，用于定义一个哈希表映射。

int hello(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; // bpf_get_current_uid_gid() 是一个辅助函数，用于获取触发此 kprobe 事件的进程的用户 ID。
   p = counter_table.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&uid, &counter); // 不同用户运行程序的次数。
   return 0;
}
"""

b = BPF(text=program)

# Attach to a tracepoint that gets hit for all syscalls 
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
