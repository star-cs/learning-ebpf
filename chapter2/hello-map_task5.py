#!/usr/bin/python3
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table); // BPF_HASH() 是一个 BCC 宏，用于定义一个哈希表映射。

int hello(struct bpf_raw_tracepoint_args *ctx) {
   u64 syscall_nr;
   u64 counter = 0;
   u64 *p;

   // 获取系统调用号（存储在寄存器rax中）
   syscall_nr = ctx->args[1];  
   
   p = counter_table.lookup(&syscall_nr);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&syscall_nr, &counter); // 统计特定系统调用的调用次数
   return 0;
}
"""

b = BPF(text=program)
# 改为使用原始跟踪点来捕获所有系统调用
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"Syscall {k.value}: {v.value}\t"
    print(s)
