## Examples
Before continuing, understand that an allowlist firewall blocks all network traffic by default.

Files are:
- `galaf.json` : galaf configuration file for defines and outbound rules
- `galaf_generate` : utility to generate groups, nftables includes and dnsmasq nftset files
- `nftables.conf` : example base allowlist nftables configuration with includes
- `galaf.c` and `galaf-test.c` : galaf appgroup "gatekeeper" tool
- `so_mark_giduid.bpf.c` and `so_mark_giduid.service` : eBPF socket mark tool
- `galaf_stats` : print nft sets / statistics
- `galaf_tcpdump` : tcpdump specific ct mark / user / appgroup traffic

For more information, examine the files.

## Installation
No easy to install package for the example files is provided because installing an allowlist firewall will drop or reject all network traffic and therefore break things you expect to work.  It's best that you understand, customize, configure and install an allowlist application firewall yourself.  As it is, the examples provided are minimal and principally meant as a guide and do not allowlist much of anything.

How to install them manually (as root):

Build and install the galaf tool (pre-built binary targets amd64 Debian bullseye only!):
```sh
# if using galaf.json; requires "execv" entry for every appgroup
apt install libjson-glib-dev # GLib JSON library development files
{ gcc | clang } galaf.c $(pkg-config --cflags --libs json-glib-1.0) -o galaf
install -p galaf /usr/local/bin/
setcap cap_setgid+ep /usr/local/bin/galaf # grant capabilities
# Usage: galaf appgroupname [params ...]
```
```sh
# OR (for testing) NOT using galaf.json: can execvp anything in PATH!
{ gcc | clang } galaf-test.c -o galaf-test
install -p galaf-test /usr/local/bin/galaf
setcap cap_setgid+ep /usr/local/bin/galaf # grant capabilities
# Usage: galaf appgroupname command [params ...]
```
Note: `+ep` = effective and permitted capabilities.  Effective normally for "capability-dumb binary".  Without `e` we'd call `cap_get_proc`, `cap_set_proc`, `cap_clear` (libcap, sys/capability.h).  Not really an issue with such a simple program for now... and capabilities are not inheritable via execv:
```sh
galaf-test appgroupname /usr/sbin/capsh --print # capabilities not inheritable via execv
/usr/sbin/getcap /usr/local/bin/galaf  # unprivileged user can confirm caps
```
Also: new files created may be owned by the new group (if they did not exist before).  This should not present a problem, and does show which app created new files.  Just remember that when you delete groups, you should first chown files owned by those groups (`galaf_generate` offers this option).

Optionally customize and install the `galaf.json` configuration file:
```sh
mkdir -p /usr/local/etc/galaf && cp galaf.json /usr/local/etc/galaf/
```
`galaf.json` should have three main dictionary entries:
- `config`: defines appgroup gid range, if nft table is inet or not (combined ipv4+6), nft table name and user / group defaults.
- `users`: users outbound allowlist rules
- `groups`: application groups outbound allowlist rules
	- `execv` defines the binary (_path must be fully qualified!_) and command line arguments.  Single unicode elipsis character `"…"` (<kbd>compose-key</kbd> + <kbd>.</kbd> + <kbd>.</kbd>) will be replaced by the rest of the original arguments (after appgroupname).
    - `domains` if using dnsmasq DNS based allowlist ip address sets.
		- array of strings = domain names (includes subdomains)
		- string = appgroupname to use same domains as other group.
    - `rule` and `rule6` define (_additional, if using domains_) accept rules, empty string means accept unconditionally.
    - if `domains` and `rule` are missing, then only an nft define will be generated, no rules.  In that case you can manually add allowlist rules to `nftables.conf` using those defines.

Optionally install `galaf_generate` to generate nftables include files and dnsmasq nftset configuration files:
```sh
install -p galaf_generate /usr/local/sbin/
galaf_generate # -h for help
```

Optionally build and install the `so_mark_giduid` eBPF (object file _should_ be portable):
```sh
apt install clang bpftool # gcc cannot target bpf
clang --target=bpf -O2 -c so_mark_giduid.bpf.c -o so_mark_giduid.bpf.o
# Copy eBPF object file to priviledged area:
mkdir -p /usr/local/etc/galaf && cp so_mark_giduid.bpf.o /usr/local/etc/galaf/
# Install systemd service
mkdir -p /usr/local/lib/systemd/system && cp so_mark_giduid.service /usr/local/lib/systemd/system/
# Enable service (next/every boot) and start it now
systemctl enable --now so_mark_giduid.service
```

Customize and install `nftables.conf`, and enable nftables service:
```sh
# Validate nftables.conf file
nft -cf nftables.conf
# This wil overwrite existing /etc/nftables.conf
install -pb nftables.conf /etc/
# if not already running, start nftables service:
systemctl enable --now nftables.service
# else restart it
systemctl restart nftables.service
# or simply reload
nft -f /etc/nftables.conf
```
Assuming you've already setup and configured dnsmasq your preferred way (see main [README.md](../README.md)), (re)start it:
```sh
# if dnsmasq is running as a Network Manager plugin...
systemctl restart NetworkManager
```
It's not required, but you might want to reboot to ensure all caches are flushed, and everything is loaded fresh in case any applications have already cached IP addresses prior to installation (domain based rules might not work in that case).

## How to use galaf
Let's say we have this `/usr/local/etc/galaf/galaf.json` entry under groups:
```json
		"ddgr": {
			"execv": [ "/usr/bin/ddgr", "…" ],
			"domains": [ "duckduckgo.com" ],
			"rule": "tcp dport 443"
		}
```
User can use `galaf` directly (helps with awareness of allowlist firewall):
```sh
galaf ddgr [params ...]

# Could also add galaf bash-completion to rcfile if appgroupnames == commandnames:
complete -F _command galaf
```
Or, create user galaf aliases (`~/.bash_aliases`),<br>
Or, create system wide aliases (`/etc/profile.d/galaf_aliases.sh`):
```sh
alias ddgr='galaf ddgr'
```
Or, create overrides for `/usr/bin` binaries in `/usr/local/bin` (or `~/bin`):
```sh
install <(echo -e '#!/bin/sh\nexec galaf ddgr "$@"') /usr/local/bin/ddgr
```

For desktop files, can create `/usr/local` versions with a different `Exec`:
```sh
sed 's|Exec=/usr/bin/thunderbird|Exec=galaf thunderbird|' /usr/share/applications/thunderbird.desktop > /usr/local/share/applications/thunderbird.desktop
```

<details><summary>Click for information about dbus services (Exec=gapplication launch)...</summary>

Some apps may be launched as dbus services, for example: GNOME Weather.
These can be identified by their Exec= line, which may look something like this:
```sh
grep ^Exec /usr/share/applications/org.gnome.Weather.desktop
Exec=gapplication launch org.gnome.Weather
```
In that case gapplication is launching a dbus service file:
```sh
grep ^Exec /usr/share/dbus-1/services/org.gnome.Weather.service
Exec=/usr/share/org.gnome.Weather/org.gnome.Weather --gapplication-service
```
So if we have in `galaf.json`:
```json
		"gnomeWeather": {
			"execv": [ "/usr/share/org.gnome.Weather/org.gnome.Weather", "--gapplication-service" ],
			"domains": [ "api.met.no", "www.aviationweather.gov" ]
```
We can copy and modify the dbus service file to a `/usr/local` one:
```sh
sed 's|^Exec=.*|Exec=/usr/local/bin/galaf gnomeWeather|' /usr/share/dbus-1/services/org.gnome.Weather.service /usr/local/share/dbus-1/services/org.gnome.Weather.service
```
And, if it's not already configured, we also need (first/one time only) to add local modifications to dbus search path:
```xml
cat > /etc/dbus-1/session-local.conf << "EOF"
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>

  <!-- Search for .service files in /usr/local -->
  <servicedir>/usr/local/share/dbus-1/services</servicedir>

</busconfig>
EOF
```
The above should work for the GNOME Weather app, however it will not work for weather info in your GNOME notifications, because `gnome-shell` is the app fetching that!  So, after all, the easiest might be to give user allowlist access to the weather domains instead if you really wish... or use a command line, or web based, weather app ;)

</details>

Optionally install the `galaf_stats` and `galaf_tcpdump` tools for root:
```sh
install -p galaf_stats galaf_tcpdump /usr/local/sbin/

head galaf_tcpdump # show examples

galaf_stats # does not require parameters
```
