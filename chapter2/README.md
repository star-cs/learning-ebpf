# Chapter 2

You'll need [BCC](https://github.com/iovisor/bcc) installed for the examples in this directory.

# [hello.py](./hello.py)
simple example that emits trace messages triggered by a `kprobe`  
通过绑定到 execve 系统调用，每当运行程序，就会输出`bpf_trace_printk`。


# [hello-file.py](./hello-file.py) 
similar simple example, attached to a syscall entry `tracepoint`   
通过绑定 tracepoint `sys_enter_openat`，记录打开文件事件 文件名以及进程名
> BCC提供 TRACEPOINT_PROBE 宏便捷绑定 tracepoint 
> `bpftrace -vl tracepoint:syscalls:sys_enter_openat` 查询 tracepoint sys_enter_openat 参数类型

# kprobe 和 tracepoint   
bpftrace，只有 Tracepoint 类型的探针可以通过 -vl 查询到预定义的参数结构，而其他动态探针（如 kprobe/kretprobe）无法直接通过该命令获取参数定义。  
> Tracepoint 是内核开发者预先植入的静态跟踪点，其参数名称、类型和偏移量在编译时已固化。


# [hello-map.py](./hello-map.py)
introduce the concept of a BPF map     
通过绑定到 execve 系统调用，统计不同用户运行程序的次数  
> `BPF_HASH()` 是一个 BCC 宏，用于定义一个哈希表映射。


# [hello-buffer.py](./hello-buffer.py)
use a ring buffer to convey information to user space 
绑定 execve 系统调用，记录运行程序的 pid，uid，可执行文件名 和 消息（默认设置）
通过 events 提交数据到Perf缓冲区

当需要从内核态向用户态传递复杂结构体​（例如包含进程名、文件名、返回值等）而非简单整数时，需使用 events 机制。

> `BPF_PERF_OUTPUT(output);`  // 定义Perf事件映射，用于向用户空间传递数据  
> `bpf_get_current_comm(&data.command, sizeof(data.command));` 获取进行的可执行文件名称  
> `bpf_probe_read_kernel(&data.message, sizeof(data.message), message);` 安全读取内核数据到结构体  
> `output.perf_submit(ctx, &data, sizeof(data)); ` // 提交数据到Perf缓冲区  
> `ctx 参数是内核自动传递给 eBPF 处理函数的执行上下文`


# [hello-file-ring-buffer.py](./hello-file-ring-buffer.py)
like hello-file but passing information using a ring buffer  

# [hello-tail.py](./hello-tail.py) 
simple demo of eBPF tail calls，尾调用  
> `BPF_PROG_ARRAY(syscall, 500);`  // 定义`程序数组类型`的映射（BPF_MAP_TYPE_PROG_ARRAY）
> `syscall.call(ctx, opcode);  // 根据系统调用号查找并执行对应的处理程序`

```c
struct bpf_raw_tracepoint_args {
    __u64 args[0];                  // 指向具体的参数
};
```

> `bpftrace -lv 'tracepoint:raw_syscalls:sys_enter'`查询到bpf_raw_tracepoint_args对应的结构体内容
```bash
tracepoint:raw_syscalls:sys_enter
    long id                         // 系统调用号（syscall number）
    unsigned long args[6]           // 最多 6 个系统调用参数
```
> 例如：read(int fd, void *buf, size_t count) 会映射为：args[0]=fd, args[1]=buf, args[2]=count

raw_syscalls 只有两个
```bash
bpftrace -lv 'tracepoint:raw_syscalls:*'

tracepoint:raw_syscalls:sys_enter
    long id
    unsigned long args[6]
tracepoint:raw_syscalls:sys_exit
    long id
    long ret
```

raw_tracepoint 比普通 tracepoint 更靠近内核实现的探测点


# 练习
1. 修改 eBPF 程序 hello-buffer.py，使其对奇数和偶数进程 ID 输出不同的跟踪消息。
2. 修改 hello-map.py，使 eBPF 代码由多个系统调用触发。例如， openat() 常用于打开文件，write() 用于向文件写入数据。您可以先将 hello eBPF 程序附加到多个系统调用 kprobes。然后尝试为不同的系统调用修改 eBPF 程序 hello 的版本，证明您可以从多个不同的程序访问同一个映射。
3. eBPF 程序 hello-tail.py 是一个附加到 sys_enter 原始跟踪点的示例。任何系统调用被调用时，都会触发该跟踪点。修改 hello-map.py ，通过将其附加到相同的 sys_enter 原始跟踪点，展示每个用户 ID 发出的总系统调用的数量。 以下是我做出该修改后得到的一些示例输出：
```bash
ID 104: 6   ID 0: 225
ID 104: 6   ID 101: 34  ID 100: 45  ID 0: 332   ID 501: 19
ID 104: 6   ID 101: 34  ID 100: 45  ID 0: 368   ID 501: 38
ID 104: 6   ID 101: 34  ID 100: 45  ID 0: 533   ID 501: 57
```
4. BCC 提供的 RAW_TRACEPOINT_PROBE 宏简化了附加到原始跟踪点的过程，它会告诉用户空间 BCC 代码自动将其附加到指定的跟踪点。尝试在 hello-tail.py 中使用它，如下所示：
    - 将 hello() 函数的定义替换为 RAW_TRACEPOINT_PROBE(sys_enter)。
    - 从 Python 代码中移除显式的附加调用 b.attach_raw_tracepoint()。    
您应该会看到 BCC 自动附加，并且程序工作正常。这是 BCC 提供的许多方便宏的一个示例。
5. 您可以进一步修改 hello_map.py，使哈希表中的键标识特定的系统调用（而不是特定的用户）。输出将显示整个系统中该系统调用被调用的次数。


# 环境
```bash
sudo apt install -y zip bison build-essential cmake flex git libedit-dev libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools liblzma-dev libdebuginfod-dev arping netperf iperf

sudo ln -s /usr/bin/python3 /usr/bin/python
```

## BCC
```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 ..
pushd src/python/
make
sudo make install
popd
```

```
cd /usr/share/bcc/tools
sudo ./execsnoop
```

## bpftrace
```bash
apt-get install -y bpftrace # 0.14.0
```