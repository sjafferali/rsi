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

### PROCESSOR
print_info "CPU: `cat /proc/cpuinfo  | grep "model name" | awk -F: '{print$2}' | egrep -o "[a-zA-Z0-9].*" | head -1 | sed 's/  */ /g'` (`cat /proc/cpuinfo  | grep "model name" | wc -l` Cores)"

### CONTROL PANEL CHECK
if [[ `rpm -q psa | grep -v installed | wc -l` -ge 1 ]]
then
	print_info "Control Panel: Plesk (`rpm -q psa | awk -F"-" '{print$2}'`)"
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
if [[ ! -z `netstat -tlnp | egrep ":80 .*LISTEN" | awk -F/ '{print$2}' | sort | uniq` ]]
then
	print_info "Port 80: `netstat -tlnp | egrep ":80 .*LISTEN" | awk -F/ '{print$2}' | sort | uniq | head -1`"
fi

### RECAP CHECK
if [[ -f /etc/cron.d/rs-sysmon ]]
then
	print_info "Rs-sysmon: installed"
elif [[ -f /etc/cron.d/recap ]]
then
	print_info "Recap: installed"
else
	print_warn "Neither Rs-sysmon or Recap is installed."
	print_sub "https://github.com/rackerlabs/recap"
fi

### HOLLAND CHECK
if [[ -f /usr/sbin/holland ]]
then
	print_info "Holland: installed"
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
if [[ -f /var/log/messages ]]
then
	ooms=`egrep "oom|Out of memory|out_of_memory" /var/log/messages | wc -l`
	if [[ $ooms -ge 1 ]]
	then
		print_warn "Found $ooms OOM events in /var/log/messages"
		egrep "oom|Out of memory|out_of_memory" /var/log/messages | tail | while read line
		do
			print_sub "$line"
		done
	fi
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
		if [[ ! -z `grep racker /var/log/secure | grep "/dev/pts/$otherpts" | tail -1` ]]
		then
			print_sub "`grep racker /var/log/secure | grep "/dev/pts/$otherpts" | tail -1`"
		fi
	done
fi

### INODES CHECK
df -Pi | egrep "(100|9[897])%" | while read line
do
	print_warn "Inode utilization at `echo $line | awk '{print$5}'` on `echo $line | awk '{print$6}'`"

done

### DISK CHECK
df -Ph | egrep "(100|9[897])%" | while read line
do
        print_warn "Disk utilization at `echo $line | awk '{print$5}'` on `echo $line | awk '{print$6}'`"

done

### SHELL CHECK
if [[ $SHELL != "/bin/bash" ]]
then
	print_warn "Current shell is not /bin/bash ($SHELL)"
fi

exit 
}


vhost_check () {
conf_file=`httpd -S 2>&1 | grep " $1" | awk -F'(' '{print$2}' | awk -F')' '{print$1}' | awk -F':' '{print$1}' | head -1`
line_number=`httpd -S 2>&1 | grep " $1" | awk -F')' '{print$1}' | awk -F'(' '{print$2}' | awk -F':' '{print$2}' | head -1`
if [[ -z $conf_file ]]
then
	echo "[!] Not found."
	exit 1 ;
fi 
doc_root=`cat -n $conf_file | egrep -A50 "^\s*$line_number" | grep DocumentRoot | head -1 | awk '{print$3}'`
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
	cat -n $conf_file | grep -Po "(?s)^\s+$line_number.*?</VirtualHost>"
fi
}


check_log () {
if [[ $R_TMP -eq 1 ]]
then
        TMP=$log_file
else
        TMP=`mktemp`
        cat /dev/stdin > $TMP ;
fi

echo -e "\n=== Top IP Addresses ==="
cat $TMP | awk '{print$1}' | sort | uniq -c | sort -nr | head
echo -e "\n=== Top Resources ==="
cat $TMP | awk -F'"' '{print$2}' | sort | uniq -c | sort -nr | head
echo -e "\n=== Top Response Codes  ==="
cat $TMP | awk -F'"' '{print$3}' | awk '{print$1}' | sort | uniq -c | sort -nr | head
echo -e "\n=== Top Referrers ==="
cat $TMP | awk -F'"' '{print$4}' | sort | uniq -c | sort -nr | head
echo -e "\n=== Top User Agents ==="
cat $TMP | awk -F'"' '{print$6}' | sort | uniq -c | sort -nr | head

if [[ $R_TMP -eq 0 ]]
then
        rm -f $TMP
fi
}



rbl_check () {
if [[ -z $ip_addr ]]
then
	ip_addr=`curl -s --insecure curlmyip.com`
fi
oct1=`echo $ip_addr | awk -F"." '{print$1}'`
oct2=`echo $ip_addr | awk -F"." '{print$2}'`
oct3=`echo $ip_addr | awk -F"." '{print$3}'`
oct4=`echo $ip_addr | awk -F"." '{print$4}'`

blacklists=(bl.spamcop.net xbl.spamhaus.org sbl.spamhaus.org pbl.spamhaus.org dnsbl-1.uceprotect.net dnsbl.sorbs.net ips.backscatterer.org b.barracudacentral.org relays.mail-abuse.or socks.dnsbl.sorbs.net smtp.dnsbl.sorbs.net)

for i in ${blacklists[@]}
do
	if [[ ! -z `host $oct4.$oct3.$oct2.$oct1.$i | grep address` ]]
	then
		print_warn "$ip_addr listed in $i"
	else
		print_info "$ip_addr not listed in $i"
	fi
done

if [[ -z `host $ip_addr | grep address` ]]
then
	print_info "$ip_addr has PTR record."
	print_sub "`host $ip_addr`"
	IP_HOST=`host $ip_addr | awk '{print$5}'`
	if [[ $(dig $IP_HOST +short) == "$ip_addr" ]]
	then
		print_info "$IP_HOST resolves back to $ip_addr"
	else
		print_warn "$IP_HOST does NOT resolve back to $ip_addr"
	fi
else
	print_warn "$ip_addr has no PTR record."
fi

#if which telnet &> /dev/null
#then
#	BANNER=$({ sleep .4 ; echo ^] ; } | telnet $ip_addr 25 2> /dev/null | awk -F"telnet" '{print$1}' | egrep -v "Trying|Connected|Escape" | head -1)
#	if [[ -z $BANNER ]]
#	then
#		print_warn "Cannot connect to port 25 on $ip_addr"
#	else
#		print_info "Connected to port 25 on $ip_addr"
#		print_sub "$BANNER"
#	fi
#fi

exit 
}


sh_help () {
echo "
Robust System Info
Version $version

Usage: bash <(curl --insecure -s https://raw.githubusercontent.com/sjafferali/rsi/master/rsi.sh) [function] [option] [arg1]

Functions:
============================
-h: 	Shows this help
-a: 	Do general status checks
-l:	Show statistics about Apache log (pipe log entries to script)
-e:	Do email checks

-l Options:
===========================
-f [file]:	Pass log file to parse instead of using piped output

-e Options:
===========================
-i [IP] 	Specify IP address to lookup
"

exit 
}

db_create () {

db_pass="qpZ6xwcgH77NeGNYMy"
db_user="rsimport"

echo "[+] Creating user $db_user"
mysql -Ne "CREATE USER '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}'"
echo "[+] Assigning user $db_user to database $db"
mysql -Ne "GRANT ALL PRIVILEGES ON ${db}.* TO '${db_user}'@'localhost'"
echo "[+] Flushing privileges"
mysql -Ne "FLUSH PRIVILEGES"
echo
echo Temporary MySQL User: $db_user
echo Temporary MySQL Password: $db_pass
echo
echo To Import
echo "-------------------------"
echo mysql -u $db_user -p\'$db_pass\' -o $db" < [file]"
echo
echo To Remove
echo "-------------------------"
echo mysql -Ne \"DROP USER \'$db_user\'@\'localhost\'\"
echo mysql -Ne \"FLUSH PRIVILEGES\"
exit 0 
}


verbose=0
vhost=0
domain=""
R_TMP=0
log_file=""
parse_log=0
version=0.1
ip_addr=""
db=""
check_rbl=0


OPTS=`getopt -o ahi:vd:lf:e -l addtmp: -- "$@"`
eval set -- "$OPTS"
while true ; do
    case "$1" in
        -h) sh_help; shift;;
        -v) verbose=1; shift;;
        -d) domain=$2; vhost=1 ; shift 2;;
        -a) server_stats ; shift;;
        -f) log_file=$2 ; R_TMP=1 ; shift 2 ;;
        -l) parse_log=1 ; shift ;;
	-e) check_rbl=1 ; shift ;;
	-i) ip_addr=$2 ; shift 2 ;;
	"--addtmp") db=$2 ; db_create ; shift 2 ;;
	--) shift; break;;
    esac
done

if [[ $parse_log -eq 1 ]]
then
        check_log
	exit 
fi

if [[ $vhost -eq 1 ]]
then
	vhost_check $domain
	exit
fi

if [[ $check_rbl -eq 1 ]]
then
	rbl_check
	exit
fi


sh_help 
