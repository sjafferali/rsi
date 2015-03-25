#!/bin/bash

print_info () {
echo "[INFO] * $1"
}

print_warn () {
echo "[WARN] * $1"
}

print_sub () {
echo -e "\t - $1"
}

server_stats () {
print_info "OS: `cat /etc/redhat-release | head -1`"
if [[ `rpm -q psa | grep -v installed | wc -l` -ge 1 ]]
then
	print_info "Control Panel: Plesk"
	print_sub "`rpm -q psa`"
	print_sub "admin/`if [[ $(rpm -q psa | awk -F"-" '{print$2}' | sed 's/\.//g') -le "1019" ]] ; then cat /etc/psa/.psa.shadow ; else /usr/local/psa/bin/admin --show-password ; fi`"
elif [[ -f /usr/local/cpanel/version ]]
then
	print_info "Control Panel: cPanel/WHM (`cat /usr/local/cpanel/version`)"
else
	print_info "Control Panel: None"
fi
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
	print_sub "`uptime`"
fi
ooms=`egrep "oom|Out of memory|out_of_memory" /var/log/messages | wc -l`
if [[ $ooms -ge 1 ]]
then
	print_warn "Found $ooms OOM events in /var/log/messages"
	egrep "oom|Out of memory|out_of_memory" /var/log/messages | tail | while read line
	do
		print_sub "$line"
	done
fi
if [[ -f /var/log/httpd/error_log ]]
then
	maxclients=`grep -i maxclients /var/log/httpd/error_log | wc -l`
	if [[ $maxclients -ge 1 ]]
	then
		print_warn "Found $maxclients MaxClient hits in /var/log/httpd/error_log"
		print_sub "`grep -i maxclients /var/log/httpd/error_log | tail -1`"
	fi
fi
if [[ `w | grep rack | wc -l` -gt 1 ]]
then
	print_warn "Another racker logged in."
	pts=`tty | awk -F/ '{print$4}'`
	otherpts=`w | grep rack | grep -v "pts/$pts" | awk '{print$2}' | awk -F/ '{print$2}'`
	print_sub "`w | grep rack | grep pts/$otherpts`"
	print_sub "`grep racker /var/log/secure | grep "/dev/pts/$otherpts" | tail -1`"
fi
echo
}


vhost_check () {
conf_file=`httpd -S 2> /dev/null | grep " $1" | awk -F: '{print$1}' | awk -F'(' '{print$2}'`
line_number=`httpd -S 2> /dev/null | grep " $1" | awk -F: '{print$2}' | awk -F')' '{print$1}'`
doc_root=`cat -n $conf_file | egrep -A50 "^ $line_number" | grep DocumentRoot | head -1 | awk '{print$3}'`
echo $1
echo Document Root: $doc_root
echo Virtual Host File: $conf_file:$line_number
echo 
print_vhost
}

print_vhost () {
if [[ $verbose -eq 1 ]]
then
	echo $conf_file:
	echo "-------------------------------"
	cat -n $conf_file | grep -Pzo "(?s)^ $line_number.*?</VirtualHost>"
fi
}

verbose=0
vhost=0
domain=""

OPTS=`getopt -o ahvd: -- "$@"`
eval set -- "$OPTS"
while true ; do
    case "$1" in
	-h) sh_help; shift;;
        -v) verbose=1; shift;;
	-d) domain=$2; vhost=1 ; shift 2;;
	-a) server_stats ; shift;;
        --) shift; break;;
    esac
done

if [[ $vhost -eq 1 ]]
then
	vhost_check $domain
fi
