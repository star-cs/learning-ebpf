# Chapter 4 - The bpf() System Call

In this chapter I'll walk you through the system calls invoked by these example
programs `hello-buffer-config.py` and `hello-ring-buffer-config.py`.

## Exercises

Example solution to using `bpftool` to update the `config` map:

```
bpftool map update name config key 0x2 0 0 0 value hex 48 65 6c 6c 6f 20 32 0 0 0 0 0
```


```c
int bpf(int cmd, union bpf_attr *attr, unsigned int size);
```

指定 -e bpf 来表示查看 bpf() 系统调用
```bash
strace -e bpf ./hello-buffer-config.py

bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_SOCKET_FILTER, insn_cnt=2, insns=0x7fff35d8ae80, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(0, 0, 0), prog_flags=0, prog_name="", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=0, func_info_rec_size=0, func_info=NULL, func_info_cnt=0, line_info_rec_size=0, line_info=NULL, line_info_cnt=0, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 148) = 3
bpf(BPF_BTF_LOAD, {btf="\237\353\1\0\30\0\0\0\0\0\0\0\374\4\0\0\374\4\0\0\340\3\0\0\1\0\0\0\0\0\0\10"..., btf_log_buf=NULL, btf_size=2292, btf_log_size=0, btf_log_level=0}, 40) = 3
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_SOCKET_FILTER, insn_cnt=2, insns=0x7fff35d8ab50, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(0, 0, 0), prog_flags=0, prog_name="libbpf_nametest", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=0, func_info_rec_size=0, func_info=NULL, func_info_cnt=0, line_info_rec_size=0, line_info=NULL, line_info_cnt=0, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 148) = 4
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_PERF_EVENT_ARRAY, key_size=4, value_size=4, max_entries=8, map_flags=0, inner_map_fd=0, map_name="output", map_ifindex=0, btf_fd=0, btf_key_type_id=0, btf_value_type_id=0, btf_vmlinux_value_type_id=0, map_extra=0}, 80) = 4
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_HASH, key_size=4, value_size=13, max_entries=10240, map_flags=0, inner_map_fd=0, map_name="config", map_ifindex=0, btf_fd=3, btf_key_type_id=1, btf_value_type_id=4, btf_vmlinux_value_type_id=0, map_extra=0}, 80) = 5
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=44, insns=0x7dc16e041000, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(6, 6, 87), prog_flags=0, prog_name="hello", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=3, func_info_rec_size=8, func_info=0x5d9eac0e8b80, func_info_cnt=1, line_info_rec_size=16, line_info=0x5d9eacab94d0, line_info_cnt=20, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 152) = 6
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=5, key=0x7dc16d84d310, value=0x7dc16d84fd90, flags=BPF_ANY}, 32) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=5, key=0x7dc16d84fd90, value=0x7dc16d84d310, flags=BPF_ANY}, 32) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7dc16d84fc90, value=0x7dc16d84d310, flags=BPF_ANY}, 32) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7dc16d84d310, value=0x7dc16d84fc90, flags=BPF_ANY}, 32) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7dc16d84fc90, value=0x7dc16d84d310, flags=BPF_ANY}, 32) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7dc16d84d310, value=0x7dc16d84fc90, flags=BPF_ANY}, 32) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7dc16d84fc90, value=0x7dc16d84d310, flags=BPF_ANY}, 32) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7dc16d84d310, value=0x7dc16d84fc90, flags=BPF_ANY}, 32) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7dc16d84fc90, value=0x7dc16d84d310, flags=BPF_ANY}, 32) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7dc16d84d310, value=0x7dc16d84fc90, flags=BPF_ANY}, 32) = 0
```

# 加载 BTF
bpf(BPF_BTF_LOAD, {btf="\237\353\1\0...}, 128) = 3
- btf_fd 3

# 创建映射
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_PERF_EVENT_ARRAY, key_size=4, value_size=4, max_entries=8, map_flags=0, inner_map_fd=0, map_name="output", map_ifindex=0, btf_fd=0, btf_key_type_id=0, btf_value_type_id=0, btf_vmlinux_value_type_id=0, map_extra=0}, 80) = 4
> 从命令名称 BPF_MAP_CREATE 推测出此调用用于创建 eBPF 映射。可以看到，这个映射的类型是 PERF_EVENT_ARRAY，名为 output。在这个 perf 事件映射中，键和值都是 4 字节长。映射中最多可以存放 4 对键值对，这由 max_entries 字段定义；我将在本章稍后解释为什么这个映射有四个条目。返回值 4 是用于用户空间代码访问 output 映射的文件描述符。

bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_HASH, key_size=4, value_size=13, max_entries=10240, map_flags=0, inner_map_fd=0, map_name="config", map_ifindex=0, btf_fd=3, btf_key_type_id=1, btf_value_type_id=4, btf_vmlinux_value_type_id=0, map_extra=0}, 80) = 5
> 这个映射被定义为哈希表映射，键为 4 字节长（对应于可以用来保存用户 ID 的 32 位整数），值为 12 字节长（与 msg_t 结构的长度相匹配）。我没有指定表的大小，因此它使用了 BCC 的默认大小，拥有 10,240 个条目。  
>  bpf() 系统调用也返回了一个文件描述符 5，该描述符将用于在将来的系统调用中引用这个 config 映射。  
> btf_fd=3，它告诉内核使用之前获得的 BTF 文件描述符 3

# 加载程序
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=44, insns=0x7dc16e041000, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(6, 6, 87), prog_flags=0, prog_name="hello", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=3, func_info_rec_size=8, func_info=0x5d9eac0e8b80, func_info_cnt=1, line_info_rec_size=16, line_info=0x5d9eacab94d0, line_info_cnt=20, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 152) = 6

- prog_type 字段描述了程序类型，这里表示它将被附加到 kprobe。您将在第 7 章中了解更多关于程序类型的信息。
- insn_cnt 字段表示“指令计数”。这是程序中的字节码指令的数量。
- 构成这个 eBPF 程序的字节码指令在 insns 字段指定的地址处的内存中保存。
- 这个程序被指定为 GPL 许可，以便它可以使用 GPL 许可的 BPF 辅助函数。
- prog_name 程序名称是 hello。
- expected_attach_type 为 BPF_CGROUP_INET_INGRESS 可能让人感到惊讶，因为它听起来像是与入站网络流量有关的东西，但您知道这个 eBPF 程序将要附加到 kprobe。实际上，expected_attach_type 字段仅用于某些程序类型，而 BPF_PROG_TYPE_KPROBE 并不是其中之一。BPF_CGROUP_INET_INGRESS 恰好是 BPF 附加类型列表中的第一个3，因此它的值为 0。
- prog_btf_fd 字段告诉内核先前加载的 BTF 数据中的哪个块与此程序一起使用。这里的值 3 对应于您从 BPF_BTF_LOAD 系统调用返回的文件描述符（与用于 config 映射的 BTF 数据块相同）。


| 文件描述符 | 代表含义              |
|------------|-----------------------|
| 3          | BTF 数据              |
| 4          | perf 缓冲区映射 output |
| 5          | 哈希表映射 config     |
| 6          | eBPF 程序 hello       |


# 从用户空间修改映射
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=5, key=0x7dc16d84d310, value=0x7dc16d84fd90, flags=BPF_ANY}, 32) = 0  
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=5, key=0x7dc16d84fd90, value=0x7dc16d84d310, flags=BPF_ANY}, 32) = 0  

BPF_MAP_UPDATE_ELEM 命令用于更新映射中的键值对。BPF_ANY 标志表示如果该键在映射中不存在，则应创建它。这里有两次这样的调用，分别对应于为两个不同用户 ID 配置的两个条目。

map_fd 字段用于标识正在操作的映射。您可以在这看到它是 5，这是先前创建 config 映射时返回的文件描述符。  

> 文件描述符是由内核为特定进程分配的，所以这个值 5 只对该特定用户空间进程有效，在该进程中运行着这个 Python 程序。  
然而，多个用户空间程序（以及内核中的多个 eBPF 程序）都可以访问相同的映射。  
两个访问内核中相同映射的用户空间程序可能被分配不同的文件描述符值；  
同样，两个用户空间程序可能对于完全不同的映射具有相同的文件描述符值。

键和值都是指针，所以无法从 strace 输出中判断键或值的数值。
```bash
$ bpftool map dump name config
[{
        "key": 501,
        "value": {
            "message": "Hi user 501!"
        }
    },{
        "key": 0,
        "value": {
            "message": "Hey root!"
        }
    }
]
```

# BPF 程序和映射引用
bpf() 系统调用将 BPF 程序加载到内核会返回一个文件描述符。在内核中，这个文件描述符是对程序的引用。发起系统调用的用户空间进程拥有这个文件描述符；当该进程退出时，文件描述符会被释放，程序的引用计数会减少。当 BPF 程序不再有任何引用时，内核会移除该程序。

当您将程序*固定（pin）*到文件系统时，会创建一个额外的引用。它们保存在内存中，这意味着在系统重启后它们将不会保留在原位置。
> bpftool prog load hello.bpf.o /sys/fs/bpf/hello

使用 ip link 命令加载 XDP 程序时，ip 命令已经完成，没有定义固定的位置，但尽管如此，bpftool 会现实 XDP 程序已经加载到内核中
> ip link set dev eth0 xdp obj hello.bpf.o sec xdp

# BPF 链接（BPF Links）
BPF 链接为 eBPF 程序与其附加的事件之间提供了一个抽象层。BPF 链接本身可以被固定到文件系统中，这为程序创建了另一个引用。


# eBPF 中涉及的其他系统调用
bpf() 系统调用，它将 BTF 数据、程序和映射，以及映射中的数据添加到内核。


## 初始化 perf 缓冲区
您已经看到了 bpf(BPF_MAP_UPDATE_ELEM) 调用，它们向config 映射中添加条目。  

bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7dc16d84fc90, value=0x7dc16d84d310, flags=BPF_ANY}, 32) = 0

映射的文件描述符是 4，它代表 output perf 缓冲区映射。


这个系统调用重复了四次，所有参数的值都相同，但无法知道在每次调用之间指针的值是否发生了变化？


显示更多系统调用
```bash
$ strace -e bpf,perf_event_open,ioctl,ppoll ./hello-buffer-config.py

...
忽略 ioctl
...
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_SOCKET_FILTER, insn_cnt=2, insns=0x7fffd78cbf40, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(0, 0, 0), prog_flags=0, prog_name="", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=0, func_info_rec_size=0, func_info=NULL, func_info_cnt=0, line_info_rec_size=0, line_info=NULL, line_info_cnt=0, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 148) = 3
bpf(BPF_BTF_LOAD, {btf="\237\353\1\0\30\0\0\0\0\0\0\0\374\4\0\0\374\4\0\0\340\3\0\0\1\0\0\0\0\0\0\10"..., btf_log_buf=NULL, btf_size=2292, btf_log_size=0, btf_log_level=0}, 40) = 3
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_SOCKET_FILTER, insn_cnt=2, insns=0x7fffd78cbc10, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(0, 0, 0), prog_flags=0, prog_name="libbpf_nametest", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=0, func_info_rec_size=0, func_info=NULL, func_info_cnt=0, line_info_rec_size=0, line_info=NULL, line_info_cnt=0, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 148) = 4
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_PERF_EVENT_ARRAY, key_size=4, value_size=4, max_entries=8, map_flags=0, inner_map_fd=0, map_name="output", map_ifindex=0, btf_fd=0, btf_key_type_id=0, btf_value_type_id=0, btf_vmlinux_value_type_id=0, map_extra=0}, 80) = 4
bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_HASH, key_size=4, value_size=13, max_entries=10240, map_flags=0, inner_map_fd=0, map_name="config", map_ifindex=0, btf_fd=3, btf_key_type_id=1, btf_value_type_id=4, btf_vmlinux_value_type_id=0, map_extra=0}, 80) = 5
bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=44, insns=0x73703024a000, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(6, 6, 87), prog_flags=0, prog_name="hello", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=3, func_info_rec_size=8, func_info=0x564b0d591340, func_info_cnt=1, line_info_rec_size=16, line_info=0x564b0df624d0, line_info_cnt=20, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 152) = 6
perf_event_open({type=0x8 /* PERF_TYPE_??? */, size=0x88 /* PERF_ATTR_SIZE_??? */, config=0, sample_period=1, sample_type=0, read_format=0, precise_ip=0 /* arbitrary skid */, ...}, -1, 0, -1, PERF_FLAG_FD_CLOEXEC) = 7
ioctl(7, PERF_EVENT_IOC_SET_BPF, 6)     = 0
ioctl(7, PERF_EVENT_IOC_ENABLE, 0)      = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=5, key=0x73702fa51310, value=0x73702fa53d90, flags=BPF_ANY}, 32) = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=5, key=0x73702fa53d90, value=0x73702fa51310, flags=BPF_ANY}, 32) = 0
ioctl(8, TCGETS, 0x7fffd78cc7b0)        = -1 ENOTTY (Inappropriate ioctl for device)
ioctl(8, TCGETS, 0x7fffd78cc600)        = -1 ENOTTY (Inappropriate ioctl for device)
perf_event_open({type=PERF_TYPE_SOFTWARE, size=0 /* PERF_ATTR_SIZE_??? */, config=PERF_COUNT_SW_BPF_OUTPUT, sample_period=1, sample_type=PERF_SAMPLE_RAW, read_format=0, precise_ip=0 /* arbitrary skid */, ...}, -1, 0, -1, PERF_FLAG_FD_CLOEXEC) = 8
ioctl(8, PERF_EVENT_IOC_ENABLE, 0)      = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x73702fa53c90, value=0x73702fa51310, flags=BPF_ANY}, 32) = 0
perf_event_open({type=PERF_TYPE_SOFTWARE, size=0 /* PERF_ATTR_SIZE_??? */, config=PERF_COUNT_SW_BPF_OUTPUT, sample_period=1, sample_type=PERF_SAMPLE_RAW, read_format=0, precise_ip=0 /* arbitrary skid */, ...}, -1, 1, -1, PERF_FLAG_FD_CLOEXEC) = 9
ioctl(9, PERF_EVENT_IOC_ENABLE, 0)      = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x73702fa51310, value=0x73702fa53c90, flags=BPF_ANY}, 32) = 0
perf_event_open({type=PERF_TYPE_SOFTWARE, size=0 /* PERF_ATTR_SIZE_??? */, config=PERF_COUNT_SW_BPF_OUTPUT, sample_period=1, sample_type=PERF_SAMPLE_RAW, read_format=0, precise_ip=0 /* arbitrary skid */, ...}, -1, 2, -1, PERF_FLAG_FD_CLOEXEC) = 10
ioctl(10, PERF_EVENT_IOC_ENABLE, 0)     = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x73702fa53c90, value=0x73702fa51310, flags=BPF_ANY}, 32) = 0
perf_event_open({type=PERF_TYPE_SOFTWARE, size=0 /* PERF_ATTR_SIZE_??? */, config=PERF_COUNT_SW_BPF_OUTPUT, sample_period=1, sample_type=PERF_SAMPLE_RAW, read_format=0, precise_ip=0 /* arbitrary skid */, ...}, -1, 3, -1, PERF_FLAG_FD_CLOEXEC) = 11
ioctl(11, PERF_EVENT_IOC_ENABLE, 0)     = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x73702fa51310, value=0x73702fa53c90, flags=BPF_ANY}, 32) = 0
perf_event_open({type=PERF_TYPE_SOFTWARE, size=0 /* PERF_ATTR_SIZE_??? */, config=PERF_COUNT_SW_BPF_OUTPUT, sample_period=1, sample_type=PERF_SAMPLE_RAW, read_format=0, precise_ip=0 /* arbitrary skid */, ...}, -1, 4, -1, PERF_FLAG_FD_CLOEXEC) = 12
ioctl(12, PERF_EVENT_IOC_ENABLE, 0)     = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x73702fa53c90, value=0x73702fa51310, flags=BPF_ANY}, 32) = 0
perf_event_open({type=PERF_TYPE_SOFTWARE, size=0 /* PERF_ATTR_SIZE_??? */, config=PERF_COUNT_SW_BPF_OUTPUT, sample_period=1, sample_type=PERF_SAMPLE_RAW, read_format=0, precise_ip=0 /* arbitrary skid */, ...}, -1, 5, -1, PERF_FLAG_FD_CLOEXEC) = 13
ioctl(13, PERF_EVENT_IOC_ENABLE, 0)     = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x73702fa51310, value=0x73702fa53c90, flags=BPF_ANY}, 32) = 0
perf_event_open({type=PERF_TYPE_SOFTWARE, size=0 /* PERF_ATTR_SIZE_??? */, config=PERF_COUNT_SW_BPF_OUTPUT, sample_period=1, sample_type=PERF_SAMPLE_RAW, read_format=0, precise_ip=0 /* arbitrary skid */, ...}, -1, 6, -1, PERF_FLAG_FD_CLOEXEC) = 14
ioctl(14, PERF_EVENT_IOC_ENABLE, 0)     = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x73702fa53c90, value=0x73702fa51310, flags=BPF_ANY}, 32) = 0
perf_event_open({type=PERF_TYPE_SOFTWARE, size=0 /* PERF_ATTR_SIZE_??? */, config=PERF_COUNT_SW_BPF_OUTPUT, sample_period=1, sample_type=PERF_SAMPLE_RAW, read_format=0, precise_ip=0 /* arbitrary skid */, ...}, -1, 7, -1, PERF_FLAG_FD_CLOEXEC) = 15
ioctl(15, PERF_EVENT_IOC_ENABLE, 0)     = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x73702fa51310, value=0x73702fa53c90, flags=BPF_ANY}, 32) = 0

```

## 附加到 Kprobe 事件




TODO：搁置，后面太细节了，看不下去了~ 