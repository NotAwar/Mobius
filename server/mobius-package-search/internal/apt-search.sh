#!/bin/bash

# Default values
SEARCH_TERM=""
EXCLUDE_TERM=""
ARCHITECTURE=""
SECTION_FILTER=""

# Parse named parameters
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --search=*) SEARCH_TERM="${1#*=}";;
    --exclude=*) EXCLUDE_TERM="${1#*=}";;
    --arch=*) ARCHITECTURE="${1#*=}";;
    --section=*) SECTION_FILTER="${1#*=}";;
    *) echo "Unknown parameter passed: $1"; exit 1;;
  esac
  shift
done

# Validate required parameters
if [[ -z "$SEARCH_TERM" || -z "$ARCHITECTURE" ]]; then
  echo "Usage: $0 --search=\"search term\" --arch=architecture [--exclude=\"exclude term\"] [--section=\"section name\"]"
  echo "  Architecture is typically amd64, i386 or all"
  exit 1
fi

# Run and format output
apt-cache dumpavail | awk -v RS= -v IGNORECASE=1 \
  -v term="$SEARCH_TERM" -v arch="$ARCHITECTURE" -v exclude="$EXCLUDE_TERM" -v section_filter="$SECTION_FILTER" '
BEGIN {
  print "["
  first = 1
}
{
  pkg = ""; desc = ""; section = ""; architecture = ""; version = ""; homepage = ""; origin = ""
  n = split($0, lines, "\n")
  for (i = 1; i <= n; i++) {
    if (lines[i] ~ /^Package:/) pkg = substr(lines[i], index(lines[i], ":") + 2)
    else if (lines[i] ~ /^Description:/) desc = substr(lines[i], index(lines[i], ":") + 2)
    else if (lines[i] ~ /^Section:/) section = substr(lines[i], index(lines[i], ":") + 2)
    else if (lines[i] ~ /^Architecture:/) architecture = substr(lines[i], index(lines[i], ":") + 2)
    else if (lines[i] ~ /^Version:/) version = substr(lines[i], index(lines[i], ":") + 2)
    else if (lines[i] ~ /^Origin:/) origin = substr(lines[i], index(lines[i], ":") + 2)
    else if (lines[i] ~ /^Homepage:/) homepage = substr(lines[i], index(lines[i], ":") + 2)
  }
  if (tolower(desc) ~ tolower(term) && architecture == arch && pkg !~ /lib/ &&
      (exclude == "" || tolower(desc) !~ tolower(exclude)) &&
      (section_filter == "" || tolower(section) == tolower(section_filter))) {
    if (!first) print ","
    printf "  {\n    \"package\": \"%s\",\n    \"architecture\": \"%s\",\n    \"section\": \"%s\",\n    \"description\": \"%s\",\n    \"version\": \"%s\",\n    \"origin\": \"%s\",\n    \"homepage\": \"%s\"\n  }", pkg, architecture, section, desc, version, origin, homepage
    first = 0
  }
}
END {
  print "\n]"
}'
