#!/bin/zsh

usage()
{
    echo "Usage: vul-per-host.sh [ -j | --json | -c | --csv | -h | --help]
        -j | --json:  json output format
        -c | --csv:   csv output format
        -h | --help:  help"
    exit 2
}

if [ -z "$1" ]; then
  format="human"
else
  case "$1" in
    -j | --json)  format="json" ;;
    -c | --csv)   format="csv" ;;
    -h | --help)  usage; exit 1 ;;
    *) echo "Unexpected option: $1"
       usage ;;
  esac
fi

temp="tmpfile.$$"
length_host=0
length_cve=0
length_fix=0

lacework vulnerability host list-cves --active --fixable --json |jq -r '.[] | select((.packages[].status == "Active") or (.packages[].status == "Reopened")) | .cve_id + " " + .packages[0].fixed_version' | while read cve fix
do
  lacework vulnerability host list-hosts $cve --online --json | jq -r '.[] |.host.hostname' | while read hostname
    do
      echo "$hostname $cve $fix" >>$temp
      (( ${#hostname} > $length_host )) && length_host=${#hostname}
    done
  (( ${#cve} > $length_cve )) && length_cve=${#cve}
  (( ${#fix} > $length_fix )) && length_fix=${#fix}
done

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
            else
                echo "$hostname,$cve,$fix"
            fi ;;
            
    human)  if [ -z "$aux" ]; then
              echo $a$b$c"|"
              a="+";b="+";c="+"
              a="${(r:$length_host+1:)a}";a=${a// /-}
              b="${(r:$length_cve+1:)b}";b=${b// /-}
              c="${(r:$length_fix+1:)c}";c=${c// /-}
              echo $a$b$c"+"
            else
              hostname="|${(r:$length_host:)hostname}"
              cve="|${(r:$length_cve:)cve}"
              fix="|${(r:$length_fix:)fix}|"
              echo $hostname$cve$fix
            fi ;;
  esac
  aux=$hostname
done
[ $format = "json" ] && echo "\n    ]\n  }\n]"
rm $temp
