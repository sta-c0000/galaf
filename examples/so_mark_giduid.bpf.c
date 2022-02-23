/*
cgroup/sock eBPF module sets SO_MARK = gid<<16 & (uid & 0xFFFF)

# Build:
clang --target=bpf -O2 -c so_mark_giduid.bpf.c -o so_mark_giduid.bpf.o

Use systemd so_mark_giduid.service to load and attach
*/

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>

SEC( "cgroup/sock" )
int so_mark_giduid( struct bpf_sock *sk ) {
    // BPF_CGROUP_RUN_PROG_INET_SOCK called by: net/ipv4/af_inet.c net/ipv6/af_inet6.c
    // So should only get IP traffic (sk->family == AF_INET || sk->family == AF_INET6)
    __u64 gid_uid = bpf_get_current_uid_gid();
    __u32 uid = gid_uid & 0xFFFF;
    // differentiate root user from unmarked (LSB declares "daemon" legacy)
    if( uid == 0 ) uid = 1; // 1 = root or daemon!
    // packing gid and uid as two u16 into u32 SO_MARK
    sk->mark = (gid_uid >> 16 & 0xFFFF0000) | uid;
return 1; // 1 = allow, 0 = deny
}

char __license[] SEC("license") = "GPL";
