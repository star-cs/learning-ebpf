"""
syscall.call(ctx, opcode); ---> bpf_tail_call(ctx, prog_array_map, index);

尾调用允许调用一系列函数而不增加栈。这在 eBPF 中特别有用，因为栈被限制为 512 字节。

BCC 提供的 RAW_TRACEPOINT_PROBE 宏简化了附加到原始跟踪点的过程，
它会告诉用户空间 BCC 代码自动将其附加到指定的跟踪点。
"""

#!/usr/bin/python3
from bcc import BPF
import ctypes as ct

# 定义 eBPF 程序代码（在用户空间以字符串形式嵌入）
program = r"""
// 定义程序数组类型的映射（BPF_MAP_TYPE_PROG_ARRAY），命名为 syscall，支持 500 个条目
BPF_PROG_ARRAY(syscall, 500);  

// 主处理函数：所有系统调用的入口点
RAW_TRACEPOINT_PROBE(sys_enter) {
    int opcode = ctx->args[1];  // 从上下文获取系统调用号（位于 args[1]）
    syscall.call(ctx, opcode);  // 根据系统调用号查找并执行对应的处理程序
    bpf_trace_printk("Another syscall: %d", opcode);  // 打印所有系统调用的通用日志
    return 0;
}

// execve 系统调用（59号）的处理函数
int hello_exec(void *ctx) {
    bpf_trace_printk("Executing a program");  // 专用日志
    return 0;
}

// 定时器相关系统调用的处理函数
int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];  // 获取定时器操作的系统调用号
    switch (opcode) {
        case 222:  // timer_create
            bpf_trace_printk("Creating a timer");
            break;
        case 226:  // timer_delete
            bpf_trace_printk("Deleting a timer");
            break;
        default:   // 其他定时器操作 (223/224/225)
            bpf_trace_printk("Some other timer operation");
            break;
    }
    return 0;
}

// 空操作处理函数（用于忽略不需要的系统调用）
int ignore_opcode(void *ctx) {
    return 0;  // 无任何操作
}
"""

# 初始化 BPF 环境
b = BPF(text=program)
# 将 hello 函数附加到 sys_enter 原始跟踪点（所有系统调用入口）
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# 加载各子处理函数并获取其文件描述符
ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

# 获取 syscall 程序数组映射的引用
prog_array = b.get_table("syscall")

# 初始化：将所有系统调用号默认指向 ignore_opcode（500个条目）
for i in range(500):
    prog_array[ct.c_int(i)] = ct.c_int(ignore_fn.fd)

# 特殊配置：为特定系统调用号绑定处理函数
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)  # execve
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)  # timer_create
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)  # timer_gettime
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)  # timer_settime
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)  # timer_getoverrun
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)  # timer_delete

# 持续读取并打印内核调试输出（/sys/kernel/debug/tracing/trace_pipe）
b.trace_print()

"""
59: execve 系统调用（执行新程序）

222-226: Linux 定时器系统调用族

222: timer_create

223: timer_gettime

224: timer_settime

225: timer_getoverrun

226: timer_delete
"""
