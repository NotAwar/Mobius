#!/bin/bash

# Script to replace all mobius-related content in files with mobius equivalents
# This script performs comprehensive content replacement

set -e

echo "Starting comprehensive content replacement..."

# Function to safely replace content in files
replace_in_file() {
    local file="$1"
    if [ -f "$file" ]; then
        echo "Processing: $file"
        # Create backup
        cp "$file" "$file.backup"
        
        # Apply all replacements
        sed -i '' \
            -e 's/mobiusmdm\.com/mobiusmdm.com/g' \
            -e 's/github\.com\/mobiusmdm/github.com\/mobiusmdm/g' \
            -e 's/mobiusmdm\/mobius/mobiusmdm\/mobius/g' \
            -e 's/mobiusmdm/mobiusmdm/g' \
            -e 's/mobiuscli/mobiuscli/g' \
            -e 's/mobiusdaemon/mobiusdaemon/g' \
            -e 's/mobius\([[:space:]]\)/mobius\1/g' \
            -e 's/mobius$/mobius/g' \
            -e 's/mobius\./mobius\./g' \
            -e 's/mobius\-/mobius-/g' \
            -e 's/mobius_/mobius_/g' \
            -e 's/mobius:/mobius:/g' \
            -e 's/mobius;/mobius;/g' \
            -e 's/mobius,/mobius,/g' \
            -e 's/mobius)/mobius)/g' \
            -e 's/mobius\]/mobius]/g' \
            -e 's/mobius}/mobius}/g' \
            -e 's/(mobius/(mobius/g' \
            -e 's/\[mobius/[mobius/g' \
            -e 's/{mobius/{mobius/g' \
            -e 's/"mobius"/"mobius"/g' \
            -e "s/'mobius'/'mobius'/g" \
            -e 's/`mobius`/`mobius`/g' \
            -e 's/Mobius\([[:space:]]\)/Mobius\1/g' \
            -e 's/Mobius$/Mobius/g' \
            -e 's/Mobius\./Mobius\./g' \
            -e 's/Mobius\-/Mobius-/g' \
            -e 's/Mobius_/Mobius_/g' \
            -e 's/Mobius:/Mobius:/g' \
            -e 's/Mobius;/Mobius;/g' \
            -e 's/Mobius,/Mobius,/g' \
            -e 's/Mobius)/Mobius)/g' \
            -e 's/Mobius\]/Mobius]/g' \
            -e 's/Mobius}/Mobius}/g' \
            -e 's/(Mobius/(Mobius/g' \
            -e 's/\[Mobius/[Mobius/g' \
            -e 's/{Mobius/{Mobius/g' \
            -e 's/"Mobius"/"Mobius"/g' \
            -e "s/'Mobius'/'Mobius'/g" \
            -e 's/`Mobius`/`Mobius`/g' \
            -e 's/FLEET/MOBIUS/g' \
            -e 's/mobiusicons/mobiusicons/g' \
            -e 's/MobiusIcon/MobiusIcon/g' \
            -e 's/MobiusMarkdown/MobiusMarkdown/g' \
            -e 's/MobiusDesktop/MobiusDesktop/g' \
            -e 's/MobiusDetails/MobiusDetails/g' \
            -e 's/MobiusMarkdown/MobiusMarkdown/g' \
            -e 's/MobiusIcon/MobiusIcon/g' \
            "$file"
        
        # Check if file changed
        if ! cmp -s "$file" "$file.backup"; then
            echo "  -> Modified"
        else
            echo "  -> No changes"
        fi
        
        # Remove backup
        rm "$file.backup"
    fi
}

# Export function so it can be used with parallel processing
export -f replace_in_file

# Find all text files and process them
find /Users/awar/Documents/Mobius \
    -type f \( \
    -name "*.go" -o \
    -name "*.js" -o \
    -name "*.ts" -o \
    -name "*.tsx" -o \
    -name "*.jsx" -o \
    -name "*.md" -o \
    -name "*.yml" -o \
    -name "*.yaml" -o \
    -name "*.json" -o \
    -name "*.html" -o \
    -name "*.ejs" -o \
    -name "*.less" -o \
    -name "*.css" -o \
    -name "*.sh" -o \
    -name "*.ps1" -o \
    -name "*.xml" -o \
    -name "*.toml" -o \
    -name "*.py" -o \
    -name "*.txt" -o \
    -name "*.cfg" -o \
    -name "*.conf" -o \
    -name "*.ini" -o \
    -name "Dockerfile*" -o \
    -name "Makefile*" -o \
    -name "*.mk" \
    \) \
    -not -path "*/node_modules/*" \
    -not -path "*/.git/*" \
    -not -path "*/build/*" \
    -not -path "*/dist/*" \
    -not -path "*/target/*" \
    -not -path "*/.terraform/*" \
    -not -name "rename_script.sh" \
    -not -name "content_replace_script.sh" | \
    while read -r file; do
        replace_in_file "$file"
    done

echo "Content replacement complete!"
