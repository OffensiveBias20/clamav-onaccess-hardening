# ClamAV On-Access Protection for Debian, Ubuntu and Kali


A Bash deployment script for ClamAV real-time/on-access protection using:
- clamd: scanning daemon
- clamonacc:on-access monitoring
- freshclam: signature updates
- systemd: service supervision, restart policy and failure alerts
- AppArmor: confinement checks when AppArmor is active
- logrotate: retention for the on-access log
The script configures recursive monitoring, prevention, optional quarantine, socket permissions, service resilience, and functional EICAR self-tests.
Status: Tested by the maintainer on Ubuntu 26.04 (Resolute) with ClamAV 1.5.4+dfsg-0ubuntu0.26.04.1. The script accepts Debian/Ubuntu/Kali systems and derivatives identified through ID/`ID_LIKE`, but that does not mean every release or derivative has been tested. Pilot it on the exact distribution and ClamAV version you intend to deploy.

## What it configures
Area:	Default behavior
Watched paths:	/home, /root, /tmp, /var/tmp, /dev/shm
Recursive monitoring:	Enabled through ClamAV DDD
On-access prevention:	Enabled
ExtraScanning:	Disabled
Quarantine:	Enabled; /var/lib/clamav-quarantine
Quarantine permissions:	root:root, mode 0700
Maximum on-access file: size	5M
Scanner account exclusion:	clamav
Internal quarantine staging exclusion:	.clamav-unlink-* paths and descendants
clamd socket:	0660, owner/group clamav:clamav when socket activation is available
On-access log:	/var/log/clamav/clamonacc.log
Log retention:	26 weekly rotations (approximately six months)
Failure handling:	systemd restart policy and clamav-alert syslog event


## The script also checks inotify directory-watch capacity, verifies the clamd socket, checks AppArmor confinement where available, and validates systemd restart/alert configuration.
Important coverage limitations
This is not a claim of complete filesystem coverage.
- /run/user/* is not monitored by default. Per-user runtime directories can contain FUSE mounts that root cannot traverse.
- Removable media is not monitored by default. Mount/unmount lifecycle handling needs a separate design, such as mount-aware scanning.
- VM and container storage is not monitored by default.
- EXCLUDE_GLOBS is empty by default. Every exclusion creates a scanning blind spot.
- OnAccessMaxFileSize 5M is the configured on-access file-size ceiling. Review this against your workload and security requirements.
- On-access protection depends on clamd being available. The script configures restart and failure-alert behavior, but on-access scanning is fail-open when the daemon is unavailable: file access may proceed without scanning. Monitor the clamav-alert event.
- Quarantine moves detected files out of their original location. This repository does not provide a quarantine restore workflow; handle quarantined files through a controlled incident-response process.
Requirements
- Debian, Ubuntu, Kali Linux, or a derivative identified by /etc/os-release
- systemd
- root privileges
- apt-get
- ClamAV packages available from configured repositories
- realpath, timeout, sort, logger, and logrotate
- AppArmor utilities are required only when AppArmor is active and the script performs its profile validation
The script installs clamav, clamav-daemon, clamav-freshclam, and logrotate.
Configuration
Review the configuration block near the top of clamav-onaccess.sh before deployment.
Watched paths
WATCH_PATHS=(
    "/home"
    "/root"
    "/tmp"
    "/var/tmp"
    "/dev/shm"
)
Add or remove paths according to your endpoint policy. Avoid overlapping paths; the script canonicalizes paths and removes duplicates/nested entries.
Exclusions
EXCLUDE_GLOBS=(
    "/home/*/.cache"
    "/root/.cache"
)
Exclusions are expanded at deployment time. Directories that do not exist at that time are skipped. Re-run the script after creating a directory you intend to exclude.
Prevention and quarantine
PREVENTION="yes"
QUARANTINE="yes"
QUARANTINE_DIR="/var/lib/clamav-quarantine"
QUARANTINE=yes requires PREVENTION=yes. The quarantine directory must be an absolute path, contain no whitespace, and not overlap any watched path. Existing quarantine directories must be real directories owned by root:root with mode 0700.

Set QUARANTINE="no" if you want prevention without moving detected files.
Other settings
- ALERT_COMMAND: optional absolute path to a root-owned, non-group/world-writable executable. It receives the failed unit name as its only argument. Use a wrapper script for more complex notification logic.
- LOG_RETENTION_WEEKS: number of weekly on-access log rotations; default 26.
- ENABLE_RELOAD: controls freshclam-to-clamd reload notifications.
- SOCKET_MODE: clamd Unix socket mode; default 0660.
Installation
Clone the repository, inspect the script, adjust its configuration, then run:
chmod 0755 clamav-onaccess.sh
sudo ./clamav-onaccess.sh
The script requires root and makes system-level changes. Do not run it blindly on a production endpoint. Test on a disposable VM or pilot machine first.
Validation performed by the script
The deployment does more than check whether services start. It performs these checks:
1. Installs or verifies the required packages.
2. Checks watched-directory count against the current inotify watch limit.
3. Preserves the original ClamAV configuration and snapshots files/systemd state it changes.
4. Reconciles its managed configuration block while preserving unrelated administrator directives.
5. Validates quarantine and temporary-directory placement.
6. Checks the expanded AppArmor profile when AppArmor is active.
7. Starts clamd and waits for its Unix socket to answer.
8. Tests clamd detection with a gzip-compressed EICAR test file.
9. Verifies socket permissions and checks that an unprivileged nobody account cannot access the socket.
10. Starts clamonacc, checks for unexpected scanner errors, and performs an EICAR prevention/quarantine test in a newly created nested directory.
11. Checks systemd restart limits and failure-alert wiring.
12. Starts freshclam and enables the services after functional checks pass.
EICAR is a harmless anti-malware test string, not live malware.
Post-installation checks
# Service state
systemctl is-active clamav-daemon clamav-freshclam clamonacc

# Effective on-access directives
sudo grep -E 'OnAccess|OnAccessExclude' /etc/clamav/clamd.conf

# Recent on-access service journal
sudo journalctl -u clamonacc --since "24 hours ago" --no-pager

# On-access log
sudo tail -n 100 /var/log/clamav/clamonacc.log

# Scanner errors and warnings
sudo journalctl -u clamonacc --since "24 hours ago" --no-pager \
  | grep -Ei 'ERROR:|WARNING:|Can't unlink'

# Quarantine permissions
sudo stat -c '%U:%G %a %n' /var/lib/clamav-quarantine

# clamd resident memory
ps -o pid,rss,%mem,etime,cmd -C clamd

# Failure alerts
sudo journalctl -t clamav-alert
Run the checks again after a period of normal workload. A successful deployment self-test proves the tested path and behavior at that moment; it does not prove that every filesystem location or workload is covered.
Files changed
The script manages or may create/update:
- /etc/clamav/clamd.conf
- /etc/systemd/system/clamonacc.service
- /etc/systemd/system/clamav-daemon.service.d/10-onaccess-resilience.conf
- /etc/systemd/system/clamav-daemon.socket.d/10-onaccess-hardening.conf (when socket activation is present)
- /etc/systemd/system/clamav-alert@.service
- /etc/logrotate.d/clamonacc
- /var/lib/clamav/clamd-tmp
- /var/lib/clamav-quarantine (when quarantine is enabled)
- /var/log/clamav/clamonacc.log
A timestamped pre-deployment clamd.conf backup is created beside the original configuration.
Rollback behavior
If deployment fails after the transaction begins, the script attempts to restore the configuration files and service state it changed.

Rollback is not a full system snapshot. It does not undo APT package installation/upgrades or downloaded signature databases. Review the rollback log and preserved snapshot directory if rollback is triggered.
Troubleshooting
Useful commands:
sudo systemctl cat clamonacc.service
sudo systemctl cat clamav-daemon.service
sudo systemctl cat clamav-daemon.socket
sudo journalctl -u clamonacc -b --no-pager
sudo journalctl -u clamav-daemon -b --no-pager
sudo aa-status
Do not broadly whitelist scanner errors just to make deployment pass. Unexpected clamonacc errors can indicate incomplete on-access coverage. Investigate the exact error and path before changing the health check.
Before production rollout
- [ ] Test on the exact OS release and ClamAV package version.
- [ ] Review WATCH_PATHS, EXCLUDE_GLOBS, and the 5 MiB on-access size limit.
- [ ] Confirm the quarantine directory is outside watched paths and has restrictive permissions.
- [ ] Confirm alert delivery reaches the team that owns endpoint protection.
- [ ] Confirm log forwarding and retention meet your organization's requirements.
- [ ] Observe the endpoint under normal workload and inspect scanner logs.
- [ ] Document paths and file types not covered by the deployment.
- [ ] Define an approved quarantine triage and restoration procedure.
License
No license is included yet. Add a license file before inviting reuse or redistribution; without an explicit license, standard copyright restrictions apply.
