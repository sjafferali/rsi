#!/bin/bash

print_info () {
echo "[INFO] * $1"
}

print_warn () {
echo "[WARN] * $1"
}

print_info "`cat /etc/redhat-release | head -1`"
cpus=`cat /proc/cpuinfo  | grep processor | wc -l`
load=`cat /proc/loadavg | awk -F. '{print$1}'`
if [[ $load -gt $cpus ]]
then
	print_warn "High load detected: `cat /proc/loadavg`"
fi
up_time=`cat /proc/uptime | awk -F. '{print$1}'`
if [[ $up_time -lt 86400 ]]
then
	print_warn "System was rebooted recently."
	echo -ne "\n\t - "`uptime`
fi
ooms=`egrep "oom|Out of memory|out_of_memory" /var/log/messages | wc -l`
if [[ $ooms -ge 1 ]]
then
	print_warn "Found $ooms OOM events in /var/log/messages"
	egrep "oom|Out of memory|out_of_memory" /var/log/messages | tail | while read line
	do
		echo -ne "\n\t - $line"
	done
fi
maxclients=`grep -i maxclients /var/log/httpd/error_log | wc -l`
if [[ $maxclients -ge 1 ]]
then
	print_warn "Found $maxclients MaxClient hits in /var/log/httpd/error_log"
	echo -ne "\n\t - "`grep -i maxclients /var/log/httpd/error_log | tail -1`
fi
if [[ `w | grep rack | wc -l` -gt 1 ]]
then
	print_warn "Another racker logged in."
	pts=`tty | awk -F/ '{print$4}'`
	otherpts=`w | grep rack | grep -v "pts/$pts" | awk '{print$2}' | awk -F/ '{print$2}'`
	echo -ne "\t - "`w | grep rack | grep pts/$otherpts`
	echo -ne "\n\t - "`grep racker /var/log/secure | grep "/dev/pts/$otherpts" | tail -1`
fi
if [[ `rpm -q psa | grep -v installed | wc -l` -ge 1 ]]
then
	print_warn "Plesk is installed."
	echo -ne "\n\t - "`rpm -q psa`
	echo -ne "\n\t - admin/"`if [[ $(rpm -q psa | awk -F"-" '{print$2}' | sed 's/\.//g') -le "1019" ]] ; then cat /etc/psa/.psa.shadow ; else /usr/local/psa/bin/admin --show-password ; fi`
fi
if [[ -f /usr/local/cpanel/version ]]
then
	print_warn "cPanel is installed."
	echo -ne "\n\t - "`cat /usr/local/cpanel/version`
fi
echo
echo
