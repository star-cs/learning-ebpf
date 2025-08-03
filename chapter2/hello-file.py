#!/usr/bin/python3  
from bcc import BPF

program = r"""
// 这里是 tracepoint，使用使用 args->filename 获取
// 可以通过 bpftrace -vl tracepoint:syscalls:sys_enter_openat 查询参数
TRACEPOINT_PROBE(syscalls, sys_enter_openat) 
{
  char command[256];

  bpf_get_current_comm(command, sizeof(command));

  bpf_trace_printk("File %s", args->filename);
  bpf_trace_printk("     opened by:%s", command);

  return 0;
}
"""

b = BPF(text=program)
b.trace_print()

