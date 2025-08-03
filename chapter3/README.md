-# Chapter 3 - Anatomy of an eBPF Program

Make sure you have installed libbpf and its header files as described in the
main [README file](../README.md).

You should then be able to build the example code as an object file by running
`make` in this directory. See Chapter 3 of the book for instructions on what to
do with this object file.

# 编译 加载
1. hello.bpf.c --> hello.bpf.o
2. bpftool prog load hello.bpf.o /sys/fs/bpf/hello 编译的目标文件中加载 eBPF 程序，并将其“固定”到位置 /sys/fs/bpf/hello
3. `ls /sys/fs/bpf` 查看
4. `bpftool prog list` 列出加载到内核中的所有程序
```bash
178: xdp  name hello  tag 4ae0216d65106432  gpl
        loaded_at 2025-08-03T20:23:17+0800  uid 0
        xlated 168B  jited 116B  memlock 4096B  map_ids 43,44
        btf_id 81
```
5. `bpftool prog show id 178 --pretty`
```bash
{
    "id": 178,
    "type": "xdp",
    "name": "hello",
    "tag": "4ae0216d65106432",
    "gpl_compatible": true,
    "loaded_at": 1754224316,
    "uid": 0,
    "orphaned": false,
    "bytes_xlated": 168,
    "jited": true,
    "bytes_jited": 116,
    "bytes_memlock": 4096,
    "map_ids": [72,73
    ],
    "btf_id": 151
}
```
# 附加到事件
程序类型必须与其附加的事件类型匹配  
`bpftool net attach xdp id 178 dev eth0`
> net attach 网络附加  
> xdp 网络数据包到达驱动层时触发执行   
> dev eth0 指定的设备

> libbpf: Kernel error message: hv_netvsc: XDP: not support LRO  
> Error: interface xdp attach failed: Operation not supported
> 禁用 LRO
> ethtool -K eth0 lro off

`bpftool net list` 查看所有网络附加的 eBPF 程序
```bash
xdp:
eth0(2) driver id 178

tc:

flow_dissector:

netfilter:
```

`ip link` 检查网络接口
```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST> mtu 1500 xdp qdisc mq state DOWN mode DEFAULT group default qlen 1000
    link/ether 8c:8c:aa:5c:5a:31 brd ff:ff:ff:ff:ff:ff
    prog/xdp id 178 tag 4ae0216d65106432 jited 
```
用于将流量发送到本机进程的回环接口 lo，以及将本机连接到外界的 eth0 接口。   
此输出还显示 eth0 有一个 JIT 编译的 eBPF 程序，其 ID 为 178，标签为 4ae0216d65106432，附加到其 XDP 钩子上。

`cat /sys/kernel/debug/tracing/trace_pipe` 每当接收到网络数据包时，eBPF 程序 hello 会产生跟踪输出。  
`bpftool prog tracelog` 获得相同的输出 

# 全局变量
`bpftool map list` 显示加载到内核中的映射

`bpftool map dump name hello.bss` 
bss6 段通常保存全局变量  
```bash
[{
        "value": {
            ".bss": [{
                    "counter": 0
                }
            ]
        }
    }
]
```
# 分离程序 
`bpftool net detach xdp dev eth0`

`bpftool net list` 验证

# 卸载程序
`rm /sys/fs/bpf/hello`

# BPF 到 BPF 调用
1. bpftool prog load hello-func.bpf.o /sys/fs/bpf/hello
2. bpftool prog list name hello
3. bpftool prog dump xlated name hello
> 由于栈大小限制为 512 字节，因此 BPF 到 BPF 的调用不能嵌套得太深。


# 练习
1. 尝试使用如下所示的 ip link 命令来附加和分离 XDP 程序：
```bash
$ ip link set dev eth0 xdp obj hello.bpf.o sec xdp
$ ip link set dev eth0 xdp off
```

2. 运行第 2 章中的任何 BCC 示例。当程序正在运行时，在第二个终端窗口使用 bpftool 检查加载的程序。以下是我运行 hello-map.py 示例时看到的内容：
```bash
$ bpftool prog show name hello
197: kprobe name hello tag ba73a317e9480a37 gpl
    loaded_at 2022-08-22T08:46:22+0000 uid 0
    xlated 296B jited 328B memlock 4096B map_ids 65
    btf_id 179
    pids hello-map.py(2785)
```
您还可以使用 bpftool prog dump 命令查看这些程序的字节码和机器码。

3. 在 chapter2 目录下运行 hello-tail.py，当它运行时，看看它加载的程序。当它正在运行时，查看它加载的程序。您将看到每个尾调用程序被单独列出，如下所示：
```bash
$ bpftool prog list
...
120: raw_tracepoint name hello tag b6bfd0e76e7f9aac gpl
    loaded_at 2023-01-05T14:35:32+0000 uid 0
    xlated 160B jited 272B memlock 4096B map_ids 29
    btf_id 124
    pids hello-tail.py(3590)
121: raw_tracepoint name ignore_opcode tag a04f5eef06a7f555 gpl
    loaded_at 2023-01-05T14:35:32+0000 uid 0
    xlated 16B jited 72B memlock 4096B
    btf_id 124
    pids hello-tail.py(3590)
122: raw_tracepoint name hello_exec tag 931f578bd09da154 gpl
    loaded_at 2023-01-05T14:35:32+0000 uid 0
    xlated 112B jited 168B memlock 4096B
    btf_id 124
    pids hello-tail.py(3590)
123: raw_tracepoint name hello_timer tag 6c3378ebb7d3a617 gpl
    loaded_at 2023-01-05T14:35:32+0000 uid 0
    xlated 336B jited 356B memlock 4096B
    btf_id 124
    pids hello-tail.py(3590)
```
您还可以使用 bpftool prog dump xlated 来查看字节码指令，并将其与“BPF 到 BPF 调用”节中的内容进行比较。

4. 请谨慎对待此问题，最好只是思考为什么会发生这种情况，而不是尝试实际操作！ `如果您从 XDP 程序返回 0 值，这对应于 XDP_ABORTED，告诉内核中止对此数据包的任何进一步处理。`考虑到在 C 中，0 通常表示成功，这可能看起来有些违反直觉，但事实就是如此。因此，如果您尝试修改程序以返回 0 并将其附加到虚拟机的 eth0 接口，则所有网络数据包都会被丢弃。如果您使用 SSH 连接到该机器，这将是非常不幸的，您可能需要重启机器才能重新获得访问权限！

您可以在容器中运行该程序，以便将 XDP 程序附加到仅影响该容器的虚拟以太网接口，而不是整个虚拟机。在 https://github.com/lizrice/lb-from-scratch 上有一个示例。


# 小结
```bash
bpftool prog load hello.bpf.o /sys/fs/bpf/hello 将目标文件加载到内核并固定（pin）到指定路径

bpftool prog list 显示所有加载的程序，包括 ID、类型、名称、内存占用等
bpftool prog show id <ID> --pretty   以 JSON 格式输出详细元数据

bpftool net attach xdp id <ID> dev eth0 将 XDP 程序附加到网络接口
bpftool net list 查看网络附加的程序
ip link 检查接口的 XDP 状态

分离与卸载
bpftool net detach xdp dev eth0
rm /sys/fs/bpf/hello


bpftool map list 显示所有映射的 ID、类型和大小

cat /sys/kernel/debug/tracing/trace_pipe 或 bpftool prog tracelog 查看程序输出
```