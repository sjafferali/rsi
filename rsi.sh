#!/bin/bash


purple="\033[35;1m"
cyan="\033[1;36m"
green="\033[32m"
yellow="\033[0;33m"
bred="\033[1;31m"
blue="\033[0;34m"
defclr="\033[0m"

if [[ `whoami` != "root" ]]
then
	echo -e "$bred[!] You are not root (`whoami`) $defclr"
	exit 1 ;
fi

print_info () {
echo -e "$yellow[INFO] *$cyan $1 $defclr"
}

print_warn () {
echo -e "$bred[WARN] * $1 $defclr"
}

print_sub () {
echo -e "\t $purple- $1 $defclr"
}

server_stats () {
print_info "OS: `cat /etc/redhat-release | head -1`"

### CONTROL PANEL CHECK
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

### MAIL SERVER CHECK
if [[ `ps aux | grep exim | wc -l` -ge 2 ]]
then
	print_info "Mailserver: `exim --version | head -1`"
elif [[ `ps aux | grep postfix | wc -l` -ge 2 ]]
then
	print_info "Mailserver: Postfix (`postconf mail_version | awk '{print$3}'`)"
elif [[ `ps aux | grep qmail | wc -l` -ge 2 ]]
then
	print_info "Mailserver: Qmail"
else
	print_info "Mailserver: None"
fi

### WEB SERVER CHECK
if [[ -z `netstat -tlnp | egrep ":80 .*LISTEN" | awk -F/ '{print$2}' | sort | uniq` ]]
then
	print_info "Port 80: `netstat -tlnp | egrep ":80 .*LISTEN" | awk -F/ '{print$2}' | sort | uniq | head -1`"
fi

### LOAD CHECK
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

### OOM CHECK
ooms=`egrep "oom|Out of memory|out_of_memory" /var/log/messages | wc -l`
if [[ $ooms -ge 1 ]]
then
	print_warn "Found $ooms OOM events in /var/log/messages"
	egrep "oom|Out of memory|out_of_memory" /var/log/messages | tail | while read line
	do
		print_sub "$line"
	done
fi

### MAXCLIENTS CHECK
if [[ -f /var/log/httpd/error_log ]]
then
	maxclients=`grep -i maxclients /var/log/httpd/error_log | wc -l`
	if [[ $maxclients -ge 1 ]]
	then
		print_warn "Found $maxclients MaxClient hits in /var/log/httpd/error_log"
		print_sub "`grep -i maxclients /var/log/httpd/error_log | tail -1`"
	fi
fi

### OTHER RACKERS LOGGED IN CHECK
if [[ `w | grep rack | wc -l` -gt 1 ]]
then
	print_warn "Other racker login sessions found."
	pts=`tty | awk -F/ '{print$4}'`
	w | grep rack | grep -v "pts/$pts" | awk '{print$2}' | awk -F/ '{print$2}' | while read otherpts
	do
		print_sub "`grep racker /var/log/secure | grep "/dev/pts/$otherpts" | tail -1`"
		print_sub "- `w | grep rack | grep pts/$otherpts`"
	done
fi

### INODES CHECK
df -i | egrep "(100|9[897])%" | while read line
do
	print_warn "Inode utilization at `echo $line | awk '{print$5}'` on `echo $line | awk '{print$6}'`"

done

### DISK CHECK
df -i | egrep "(100|9[897])%" | while read line
do
        print_warn "Disk utilization at `echo $line | awk '{print$5}'` on `echo $line | awk '{print$6}'`"

done
}


vhost_check () {
conf_file=`httpd -S 2>&1 | grep " $1" | awk -F'(' '{print$2}' | awk -F')' '{print$1}' | awk -F':' '{print$1}'`
line_number=`httpd -S 2>&1 | grep " $1" | awk -F')' '{print$1}' | awk -F'(' '{print$2}' | awk -F':' '{print$2}'`
if [[ -z $conf_file ]]
then
	echo "[!] Not found."
	exit 1 ;
fi 
doc_root=`cat -n $conf_file | egrep -A50 "^\s+$line_number" | grep DocumentRoot | head -1 | awk '{print$3}'`
echo Host: $1
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
	cat -n $conf_file | grep -Pzo "(?s)^\s+$line_number.*?</VirtualHost>"
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
