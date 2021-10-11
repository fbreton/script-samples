#!/bin/zsh

usage()
{
    echo "Usage: vul-per-host.sh [ hostname1] ... [hostnameN]
Flags:
    -j | --json   json output format
    -c | --csv    csv output format
    -e | --extip  show only host with external Ip
    -a | --active to only look about active packages
    -p  string    switch between profiles configured at ~/.lacework.toml
    -h | --help   help"
    exit 2
}

profile=""
format="human"
hostnamelist=()
ExternalIp=0
lwcmd="lacework"
active=""

while [ ! -z "$1" ]; do
  case "$1" in
    -j | --json)  [ $format = "human" ] && format="json" || usage; shift ;;
    -c | --csv)   [ $format = "human" ] && format="csv" || usage; shift ;;
    -e | --extip)  ExternalIp=1; shift ;;
    -a | --active) active="--active"; shift ;;
    -p) shift; profile=$1; lwcmd="lacework -p $1"; shift ;;
    -h | --help | -*)  usage ;;
    *) hostnamelist+=($1); shift ;;
  esac
done

eval "$lwcmd version >/dev/null 2>/dev/null" || {
  echo "ERROR The profile '$profile' could not be found.
Try running 'lacework configure --profile profile'."
  exit 2
}

temp="tmpfile.$$"
err="err.$$"
length_host=0
length_cve=0
length_fix=0
output=""

eval "$lwcmd vulnerability host list-cves $active --fixable --json" | {jq -r '.[] | select((.packages[].status == "Active") or (.packages[].status == "Reopened")) | .cve_id + " " + .packages[0].fixed_version' 2>$err} | while read cve fix
do
  eval "$lwcmd vulnerability host list-hosts $cve --online --json" | jq -r '.[] |.host.hostname + " " + .host.tags.ExternalIp' | while read hostname extip
    do
      [ $ExternalIp -eq 0 -o ! -z $extip ] && [ ${#hostnamelist} -eq 0 -o ${hostnamelist[(Ie)$hostname]} -gt 0 ] && echo "$hostname $cve $fix" >>$temp
      (( ${#hostname} > $length_host )) && length_host=${#hostname}
    done
  (( ${#cve} > $length_cve )) && length_cve=${#cve}
  (( ${#fix} > $length_fix )) && length_fix=${#fix}
done

[ -s "$err" ] && {
  eval "$lwcmd vulnerability host list-cves $active --fixable"
  rm $err
  exit 1
}

a="| Host Name"
b="| CVE ID"
c="| Fixed version"

(( (${#a}-1) > $length_host )) && ((length_host = ${#a}-1))
(( (${#b}-1) > $length_cve )) && ((length_cve = ${#b}-1))
(( (${#c}-1) > $length_fix )) && ((length_fix = ${#c}-1))

a="${(r:$length_host+1:)a}"
b="${(r:$length_cve+1:)b}"
c="${(r:$length_fix+1:)c}"

aux=""
sort $temp | while read hostname cve fix
do
  case $format in
    json)   if [ -z "$aux" ]; then
                echo "[\n  {\n    hostname: \"$hostname\",\n    cve_list: [\n      {\n        cve_id: \"$cve\"\n        fixed_version: \"$fix\"\n      }\c"
            elif [ $aux == $hostname ]; then
                echo ",\n      {\n        cve_id: \"$cve\"\n        fixed_version: \"$fix\"\n      }\c"
            else
                echo "\n    ],\n  {\n    hostname: \"$hostname\",\n    cve_list: [\n      {\n        cve_id: \"$cve\"\n        fixed_version: \"$fix\"\n      }\c"
            fi ;;
            
    csv)    if [ -z "$aux" ]; then
                echo "hostname,cve_id,fixed_version"
            fi
            echo "$hostname,$cve,$fix" ;;
            
    human)  if [ -z "$aux" ]; then
              echo $a$b$c"|"
              a="+";b="+";c="+"
              a="${(r:$length_host+1:)a}";a=${a// /-}
              b="${(r:$length_cve+1:)b}";b=${b// /-}
              c="${(r:$length_fix+1:)c}";c=${c// /-}
              echo $a$b$c"+"
            fi
            hostname="|${(r:$length_host:)hostname}"
            cve="|${(r:$length_cve:)cve}"
            fix="|${(r:$length_fix:)fix}|"
            echo $hostname$cve$fix ;;
  esac
  aux=$hostname
done
[ $format = "json" ] && echo "\n    ]\n  }\n]"
rm $temp 2>/dev/null
rm $err 2>/dev/null