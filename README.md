# Group Allow-List Application Firewall

Notes on seting up an allowlist application firewall for GNU/Linux workstations using recent versions of nftables and dnsmasq.
Assumes adequate GNU/Linux and nftables technical proficiency.  Refer to the manuals / documentation / wikis if you need help understanding the concepts or software utilized below.
There are many ways to accomplish the same thing with GNU/Linux; what's presented here is one approach for a personal workstation.
This is not a complete production ready solution, an attempt has been made to keep it as simple as possible for clarity.  As it is, some of the examples only implement security through obscurity; it is left up to the reader to customize and complete the configuration and tools.

Use of the [examples](examples/README.md) is AT YOUR OWN RISK, best to always understand before doing.

The reference platform used is a standard Debian 11 bullseye desktop install.

Sections:
- [Prerequisites](#prerequisites)
- [Why?](#why)
- [Allowlist application firewall](#allowlist-application-firewall)
- [Creating application groups](#creating-application-groups)
- [The application group gatekeeper](#the-application-group-gatekeeper)
- [Application connection tracking](#application-connection-tracking)
- [User and application tracking](#user-and-application-tracking)
- [Generating statistics](#generating-statistics)
- [Recording ip addresses by application group](#recording-ip-addresses-by-application-group)
- [Monitoring application specific traffic](#monitoring-application-specific-traffic)
- [Domain name based allowlist firewall rules](#domain-name-based-allowlist-firewall-rules)
- [Config file and Setup tool](#config-file-and-setup-tool)

## Prerequisites
- `nftables`:  syntax / functionality varies from one version to another.
- `dnsmasq-base` v2.87+: for domain name based allowlist firewall rules.
- `bpftool` if gid+uid application packet marking is desired.
- `clang`, `gcc` and tools in order to build yourself.

On recent Debian default desktop installs, both `nftables` and `dnsmasq-base` are pre-installed but not enabled (`dnsmasq v2.87` should be available in Debian 12 and can be backported).  Recent `clang/llvm` versions support `bpf` target cross compilation.  On Debian buster, `bpftool` is available in backports.

## Why?
Let's start with the assumption that we only run mostly trusted binaries on our system.  Questionable binaries should only be run on an isolated test system, VM, or at least in a container.  Online or offline, any executable can potentially cause damage; but when run offline, data from your PC risks less chance of being retrieved by a third party.  I may generally trust many executables, but I might simply rather not they unexpectedly transfer data over the internet, or might simply prefer to control when and where they do so.  Let's call it informed consent.

<details><summary>Click for more on why...</summary>

Most applications innocently access internet resources as a convenience to the user.  For example:
- GNOME desktop and applications may fetch extension updates, currency exchanges, weather info, location info, maps, other software, etc.
- Applications like Stellarium may connect to several sites to determine your location and update its databases.

Some applications will access internet resources both as a convenience to the user and for telemetry purposes:
- Firefox, an app that now generally requires full internet access (e.g. WebRTC), makes unsolicited connections itself, some of which cannot be [disabled via configuration](https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections) (_firefox.settings.services.mozilla.com_).  Other popular browsers even more so.
- Visual Studio Code is a good programmer's editor.  Open source if you compile it yourself, closed source if you download the official binary.  It, and some of its extensions, will phone home telemetry data regardless if you turn several options off in the preferences.  This is stated in their license: "*You may opt-out of many of these scenarios, but not all*".  I tried switching off all of the documented options and still `code` attempted to connect to *dc.services.visualstudio.com* and *az764295.vo.msecnd.net* and even attempts to use Google's DNS service at *2001:4860:4860::8888*.  Otherwise `code` sends telemetry data to *vortex.data.microsoft.com* constantly.
</details>

It's not that apps are bad, it's more that apps can be greedy.  Also, legitimate closed source software often attempt unsolicited network connections.  You really don't have to give every app free network reign if it's not required.

## Allowlist application firewall
The principal of an allowlist application firewall is that nothing should have access to the network unless permission has been explicitly granted.  This breaks everything that depends on the network and requires us to individually grant access to anything we want to work correctly.  So it does require some forethought and setup effort... and like many security controls, can sometimes be inconvenient.

The privileged user (root) is used to configure permissions for each application and the unprivileged users or, more specifically, apps should not be able to bypass these settings.
In the future I expect an allowlist application firewall solution will utilize something like systemd-run/nspawn cgroup v2 units/containers once it's clearer how root can enforce `systemd.resource-control` on user launched units (and systemd-resolved supports domain name allowlisting as dnsmasq does :-).

In the meantime let's setup a simple Linux group based application firewall...

## Creating application groups
### What is an application?
In this case we'll refer to application groups, not binaries.  An application group does not have a one-to-one relationship with a binary.  For example, you may have multiple Python applications that require access to different internet resources; therefore the `/usr/bin/python3` binary itself has no relation to a single application group.

We will:
- use standard Linux groups to tag "applications" and grant them firewall permissions.
- use the gid range from 30000 to 59999 as firewall application groups. With room for 30000 application groups, don't hesitate to create one for every application and service.
- not have members/users belong to any application group.  If a user were a member a group, that user application could easily grant themselves group/firewall permissions using tools like `sg`; they could also access files owned by that group, and `chmod g+s` (S_ISGID bit) files with that group; we don't want that (could also disable S_ISGID at filesystem level).  If limiting application group access by user is desired, the galaf tool (see below) could be customized to also control that.

```sh
# Create an application group using next avaible gid in our range:
groupadd -K GID_MIN=30000 -K GID_MAX=59999 appgroupname

# Get an application group gid number
getent group appgroupname

# Modify an existing application group name:
groupmod -n newappgroupname oldappgroupname

# Delete application group, after "un-owning" group tagged files (CAREFUL!):
find / -xdev ! -readable -prune -o -group appgroupname -exec chown -v :nogroup '{}' ';' && groupdel appgroupname
```

Sub-groups could also be created in dedicated ranges for specific purposes.  Generally this would be to use ranges in nftables rules for subgroups of appgroups, but it could be for other uses as well.  For example, if you wanted to allow ICMP ping access to multiple app groups:
```sh
# Create appgroup in "special" ICMP ping range (0xe000-0xe010)
groupadd -K GID_MIN=57344 -K GID_MAX=57360 traceroute
# Give ICMP ping rights to that group range
sysctl net.ipv4.ping_group_range='57344 57360'
```
Keep in mind the `ping` binary already has `cap_net_raw+ep` capabilities, so does not need this group permission.  Therefore if `traceroute` is the _only_ other ICMP ping app you need, you could instead just create an appgroup in the normal range as before, and do something like this:
```sh
# Get traceroute app group gid
gid=$(getent group traceroute | cut -d: -f3)
# Grant traceroute app group ICMP ping rights (now)
[ ! -z "$gid" ] && sysctl net.ipv4.ping_group_range="$gid $gid"
# And make it permanent (next boots)
[ ! -z "$gid" ] && echo net.ipv4.ping_group_range=$gid $gid > /etc/sysctl.d/40-allow-icmp-traceroute.conf
```

## The application group gatekeeper

### The galaf tool

To grant application group access and firewall permissions, we'll create a simple tool called `galaf` (**group allow-list application firewall**).  This gid tool will control all access to application groups and allow users to launch specific applications with specific firewall permissions.  Any time a user wants to run an application that requires net access, they issue the command `galaf appgroupname` and the tool will grant application group access (using `setregid`) and `execv` the specific binary associated with that application group.  This also allows root to enforce how the binary is launched: directly, using a systemd unit, or using a sandbox like firejail.  We'll put our tool in `/usr/local/bin` and give it `cap_setgid` capabilities.  On our workstation, the idea is not that we do not trust ourselves, the user; it's that if software are aware of a way to grant themselves network access, some will.  Note that if the target execv binary can also execv, spawn shells, or run scripts, they will also inherit the same firewall permissions; that may not be an issue if permissions are strictly limited, but try to not grant such binaries full net access, or, at least, sandbox them.

see in [examples](examples/README.md): `galaf.c` and `galaf-test.c`

## Application connection tracking

Linux kernel's netfilter takes care of connection tracking related inbound and outbound network traffic.  We can attach tag application marks using nftables connection tracking rules.  With an allowlist firewall _everything_ requiring network access needs a firewall rule, therefore we can set the conntrack mark to the application group at the same time we accept new traffic.  Netfilter will take care of tagging all related traffic with our appgroup mark.  Here is an nftables example:
```sh
define thunderbird = 30004 # define the appgroupname gid number (getent group thunderbird)
(...table)
    set thunderbird_4 { type ipv4_addr; } # allowlist IP destination addresses...
    set thunderbird_6 { type ipv6_addr; } # ...will need to be populated with elements
    (...outbound chain)
        # limit destination addresses, and tcp ports to smtps, pop3s, imaps (no web access!)
        # ...and set conntrack mark to appgroup
        skgid thunderbird ip daddr @thunderbird_4 tcp dport { 465, 587, 993, 995 } ct mark set $thunderbird accept
        skgid thunderbird ip6 daddr @thunderbird_6 tcp dport { 465, 587, 993, 995 } ct mark set $thunderbird accept
```
Once the conntrack mark is set, all related network traffic will carry that conntrack mark, both outbound and inbound traffic.

Likewise, new inbound services traffic can be marked the same way.  For example, even though sshd runs as root, we can tag it with the sshd uid to uniquely identify its traffic:
```sh
define sshd = 120 # define system user uid number (getent passwd sshd)
(...table)
    (...inbound chain)
        ip saddr 192.168.1.255/24 tcp dport 22 ct mark set $sshd accept # allow ssh in from LAN only
```
...and all related traffic, inbound and outbound, will carry that conntrack mark.

## Going further

### User **and** application tracking

We can take it further and tag all network traffic with both the user id and the group application id using nftables' conntrack mark.  The uid and gid fields are 32-bit unsigned integers, but if we limit ourselves to 16-bits, we can stuff both into the 32-bit conntrack mark.  This still provides us with tens of thousands of uids and gids for our personal workstation.  And with 16-bit uid and gid we can still take advantage of running applications in `systemd-nspawn` containers using the `--private-users` parameter and then the same application firewall rules will apply across containers (if you want different rules, you can run them in separate network namespaces; or use a different range of gids).

Unfortunately, at this time, setting the conntrack mark like this is not possible with nftables:
```sh
table inet mangle {
    type route hook output priority -150
    chain output {
        # NOT POSSIBLE! (at this time)
        ct mark set ((skgid<<16 & 0xFFFF0000) | (skuid & 0xFFFF))
    }
}
```

<details><summary>Click to see a recent nftables hack...</summary>

This `>>0` trick works with nftables 1.0.1, but not with 0.9.8 or less, and we are still not storing both gid and uid in the conntrack mark, only one or the other.  It's workable, but does not offer much benefit over manual tagging.

```sh
table inet mangle {
    chain output {
        # use type route if needed
        type filter hook output priority -150
        # skip if already marked
        ct mark != 0 accept
        # if in application gid range mark with that
        skgid 30000-59999 ct mark set skgid<<16 & 0xffff0000 accept
        # else mark with uid
        ct mark set skuid>>0 & 0xffff
    }
}
```
</details>

To accomplish this we can create a very simple eBPF program to pack the gid and uid into the socket mark when IP sockets are created.  The socket mark will be transferred to the packet mark, and the packet mark can then be transferred to the conntrack mark using nftables.

See: `socket_mark_giduid.bpf.c` in the [examples](examples/README.md) for information on how to compile, manually load and attach this eBPF program (confirm your cgroup2 root path: `mount | grep cgroup2`).  Also provided is a systemd service file to auto load the eBPF.

**NOTE**: this eBPF will NOT work properly if your system is using cgroup v1 or v1+v2 hybrid mode while using `net_cls,net_prio`!  Best to use cgroup v2 only (`systemd.unified_cgroup_hierarchy=1`), which should be the default in Debian 11 bullseye and higher.

Once our eBPF is loaded and attached, an early nftables rule can copy the packet mark to the connection tracking mark:
```sh
table inet mangle {
    chain output {
        type filter hook output priority -150
        ct mark == 0 ct mark set mark comment "copy packet mark to conntrack mark"
    }
}
```
And then all packets will be marked with both the gid and uid.  Tagging traffic with gid and uid has the advantage of allowing us to easily see what may be trying to access the network even if we did not create a rule for it...

## Generating statistics

Recent nftables versions now support dynamic set counters.  We can have nftables keep full traffic statistics by connection track mark, therefore by user and application group:
```
table inet stats {
    set post-filter-in   { type mark; counter; size 1024; flags dynamic; }
    set pre-filter-out   { type mark; counter; size 1024; flags dynamic; }
    set post-filter-out  { type mark; counter; size 1024; flags dynamic; }

    chain post-in {
        type filter hook input priority 10;
        iif lo accept comment "ignore loopback"
        update @post-filter-in { ct mark counter }
    }
    chain pre-out {
        type filter hook output priority -10;
        oif lo accept comment "ignore loopback"
        update @pre-filter-out { ct mark counter }
    }
    chain post-out {
        type filter hook output priority 10;
        oif lo accept comment "ignore loopback"
        update @post-filter-out { ct mark counter }
    }
}
```

nftables can then output these statistics in JSON format which can be processed and presented many different ways; a basic example of the kind of results this can provide:

╭─────┤ Set: pre-filter-out ├─────╮
|                user / group                 |  packets  |    bytes  |
|---------------------------------------------|----------:|----------:|
| sshd/root                                   |     1.6 k |    337 kB |
| dnsmasq/dip                                 |       47  |    3.5 kB |
| systemd-timesync/systemd-timesync           |        8  |     608 B |
| username/username                           |        5  |     300 B |
| username/firefox-esr                        |     1.3 k |  143.1 kB |
| username/ping                               |        4  |     336 B |
| username/traceroute                         |       34  |      2 kB |
| username/qalc                               |      145  |    8.3 kB |

see in [examples](examples/README.md): `nftables.conf` and `galaf_stats`

## Recording ip addresses by application group
nftables can also be used to record ip addresses specific application groups connect to, or attempt to connect to:
```sh
table inet record {
    set appgroup_out4 { type ipv4_addr; counter; size 1024; flags dynamic; }
    set appgroup_out6 { type ipv6_addr; counter; size 1024; flags dynamic; }
    chain pre-out {
        type filter hook input priority -10
        oif lo accept comment "ignore loopback"
        ct mark & 0xFFFF0000 == $appgroup update @appgroup_out4 { ip  daddr counter }
        ct mark & 0xFFFF0000 == $appgroup update @appgroup_out6 { ip6 daddr counter }
    }
}
```
To log the source and destination ipv4 addresses of inbound traffic for unmarked packets (unsolicited packets from the LAN; don't do this if you're not behind a firewalled LAN or on a DMZ PC):
```sh
table inet record {
    set unmark_in_source { type ipv4_addr; counter; size 1024; flags dynamic; }
    set unmark_in_dest   { type ipv4_addr; counter; size 1024; flags dynamic; }
    chain pre-in {
        type filter hook input priority -10
        iif lo accept comment "ignore loopback"
        ct mark 0 update @unmark_in_source { ip saddr counter }
        ct mark 0 update @unmark_in_dest   { ip daddr counter }
    }
}
```

## Monitoring application specific traffic

Now that all network traffic is tagged/marked with the uid and gid of our appgroups, we can easily monitor user/application specific traffic (inbound and outbound) using tcpdump...

see in [examples](examples/README.md): `galag_tcpdump`

For example, to see only DNS query responses for a specific appgroup:
```
galaf_tcpdump appgroupname -Klnvv | grep "q: A"
```
If you are running dnsmasq on localhost, this will show DNS queries even if the appgroup has no network access permissions in the firewall.

If you would like to know which specific binary is attempting to make connections, consider using an eBPF tool.  Several pre-built eBPF tools, like `tcpconnect-bpfcc` (TCP connects only) are available on Debian: `apt install bpfcc-tools`.  They are easy to adapt Python programs with more tools available, e.g. can `trace-bpfcc 'udp_sendmsg'` to monitor all UDP sendmsg system calls.

## Domain name based allowlist firewall rules

`dnsmasq v2.87` and up offer the `--nftset` configuration option which allows IP addresses to be automatically added to nftables set elements when domain name queries are performed.
dnsmasq can be setup different ways... use the most convenient for you.  If using a laptop with Debian's default GNOME desktop, Network Manager may be running to manage the wifi connection; in that case it's possible to use its dnsmasq plugin feature.  When using this Network Manager feature, do not install the dnsmasq package, it will conflict by also running a daemon itself; `dnsmasq-base` is all you need with Network Manager.  So, in this case, we can create `/etc/NetworkManager/conf.d/00-use-dnsmasq.conf` with:
```sh
[main]
dns=dnsmasq
```
dnsmasq configuration options can go in `/etc/NetworkManager/dnsmasq.d/00-options.conf`:
```sh
# pstree -sp $(pidof dnsmasq)       # NetworkManager runs dnsmasq in this case
# ps -wwocommand p $(pidof dnsmasq) # see command line config options already set by NM

# Prefer dnsmasq to run under its own uid instead of "nobody"
# getent passwd dnsmasq # should already exist on Debian standard install
user=dnsmasq
# Can also listen on ipv6 lo [::1]:53 with interface=lo
#interface=lo
# prevent sending LAN queries upstream
domain-needed
bogus-priv
# prevent upstream LAN ref
stop-dns-rebind
# Optionally tag DNS traffic with our appgroup gid+uid ct mark
# otherwise DNS traffic will be attributed to dnsmasq
#...it's a matter of preference for statistics / accounting
#conntrack
```
Assuming we've already created nftables sets (see above), we can now add nftset options to `/etc/NetworkManager/dnsmasq.d/40-nftsets.conf`:
```conf
nftset=/mail.myprovider.com/smtp.myprovider.com/pop3.myprovider.com/4#inet#filter#thunderbird_4/6#inet#filter#thunderbird_6
```
And then we can start dnsmasq with:
```sh
systemctl restart NetworkManager # start dnsmasq as a plugin
```

Caveats:
- nftables' `add element` does not reset timeouts if the set defines a default timeout.  It would be very useful if nftables did restart the timeouts for elements specified in `nft add element` commands. (that's an nftables issue)

- Applications that use SRV queries to get hostnames, then IP addresses, may not have those addresses added to their nft set.  Some applications may offer an option to disable SRV queries; for example `apt`'s SRV queries can be disabled with a configuration setting:
```sh
echo 'Acquire::EnableSrvRecords "false";' > /etc/apt/apt.conf.d/00noSRVqueries
```
- dnsmasq caches DNS queries, and some applications may cache ip addresses from past DNS queries.  So if you change/add set rules, or clear nftables sets, it's very important that you restart dnsmasq and all applications involved (**reboot** should work ;) to reset all of the caches; otherwise the allowlist rules and/or sets may be out of sync and network access may fail for some applications.

- dnsmasq also offers the `--connmark-allowlist` option.  You could also use this to refuse DNS queries based on the ct mark, but I really don't see the point without Ubus:  `--connmark-allowlist` does not actually prevent connections, so any app could still connect to any IP address, and use other DNS servers (like vscode does).  Even if you were to limit connections only to port 443 (https), apps could still direct connect to any IP, and even use private or public DoH (DNS over https) servers to resolve all (like firefox can do, and is considering doing by default).

## Config file and Setup tool

You can perform the steps mentioned above manually, and doing so is a good exercise to understand the process and offers the most control and flexibility.  But since the `galaf` tool would require a configuration file to specify application group command lines, that file can also be used to help setup our application groups, nftables defines, sets and rules, and the dnsmasq nftset entries...

see in [examples](examples/README.md): `galaf_conf.json` and `galaf_config`
