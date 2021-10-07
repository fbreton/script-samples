#!/bin/zsh
usage()
{
    echo "Usage: list-vuln-containner-with-specifique-tag.sh tag
Flags:
    -p  string    switch between profiles configured at ~/.lacework.toml
    -h | --help   help"
    exit 2
}

tag=""
lwcmd="lacework"
profile=""

while [ ! -z "$1" ]; do
  case "$1" in
    -p) shift; profile=$1; lwcmd="lacework -p $1"; shift ;;
    -h | --help | -*)  usage ;;
    *) [ -z "$tag" ] && tag=$1 || usage; shift ;;
  esac
done

eval "$lwcmd version >/dev/null 2>/dev/null" || {
  echo "ERROR The profile '$profile' could not be found.
Try running 'lacework configure --profile profile'."
  exit 2
}

fisrt=""
echo "["
for i in $(eval "$lwcmd vulnerability container list-assessments --json" | jq -r --arg tag "$tag" '.[] |select(any(.image_tags[]; . == $tag))|.image_digest')
do
    [ -z "$first" ] && first="no" || echo ","
    eval "$lwcmd vulnerability container show-assessment --json $i"
done
echo "]"