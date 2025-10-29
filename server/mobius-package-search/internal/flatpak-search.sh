#!/bin/bash

# Default values
SEARCH_TERM=""
EXCLUDE_TERM=""

# Parse arguments
for arg in "$@"; do
  case $arg in
    --search=*)
      SEARCH_TERM="${arg#*=}"
      shift
      ;;
    --exclude=*)
      EXCLUDE_TERM="${arg#*=}"
      shift
      ;;
    *)
      echo "Unknown option: $arg"
      echo "Usage: $0 --search=\"term\" [--exclude=\"term\"]"
      exit 1
      ;;
  esac
done

# Check if search term is provided
if [ -z "$SEARCH_TERM" ]; then
  echo "Error: --search parameter is required."
  exit 1
fi

# Get the search results
mapfile -t lines < <(flatpak search "$SEARCH_TERM" --columns=name,application,description,version)

# Remove header if present
if [[ "${lines[0]}" == *"Name"* && "${lines[0]}" == *"Application ID"* ]]; then
  unset 'lines[0]'
fi

# Start JSON array
echo "["

# Loop through lines and format as JSON
count=0
for line in "${lines[@]}"; do
  # Skip lines that contain the exclude term
  if [[ -n "$EXCLUDE_TERM" && "$line" == *"$EXCLUDE_TERM"* ]]; then
    continue
  fi

  IFS=$'\t' read -r name appid desc version <<< "$line"
  # Escape double quotes
  name=${name//\"/\\\"}
  appid=${appid//\"/\\\"}
  desc=${desc//\"/\\\"}
  version=${version//\"/\\\"}

  if [ $count -gt 0 ]; then
    echo ","
  fi

  echo "  {"
  echo "    \"name\": \"$name\","
  echo "    \"applicationId\": \"$appid\","
  echo "    \"description\": \"$desc\","
  echo "    \"version\": \"$version\""
  echo -n "  }"

  ((count++))
done

# End JSON array
echo
echo "]"

