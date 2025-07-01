#!/bin/bash

echo "=== Updating Mobius logos with new design ==="

# Source logo
SOURCE_LOGO="/Users/awar/Documents/Mobius/Mobius Logo - Simple (1).png"
ASSETS_DIR="/Users/awar/Documents/Mobius/assets/images"
WEBSITE_ASSETS_DIR="/Users/awar/Documents/Mobius/website/assets/images"

# Create backup directory
mkdir -p "/Users/awar/Documents/Mobius/logo_backups"

echo "Creating backups of existing logos..."

# Backup existing Mobius logos
find "$ASSETS_DIR" -name "*mobius*logo*" -exec cp {} "/Users/awar/Documents/Mobius/logo_backups/" \;
find "$WEBSITE_ASSETS_DIR" -name "*mobius*logo*" -exec cp {} "/Users/awar/Documents/Mobius/logo_backups/" \;

echo "Replacing main logo files..."

# Replace key logo files with the new design
# Main SVG logo (this will be used as the primary logo)
cp "$SOURCE_LOGO" "$ASSETS_DIR/mobius-logo.png"

# Text-based logos (for headers, etc.)
cp "$SOURCE_LOGO" "$ASSETS_DIR/mobius-logo-text-white.png"
cp "$SOURCE_LOGO" "$ASSETS_DIR/mobius-logo-text-black.png"

# Color logos
cp "$SOURCE_LOGO" "$ASSETS_DIR/mobius-logo-color@2x.png"

# Sized versions
cp "$SOURCE_LOGO" "$ASSETS_DIR/mobius-logo-blue-118x41@2x.png"
cp "$SOURCE_LOGO" "$ASSETS_DIR/mobius-logo-blue-118x41@2x-1.png"

# Website versions
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/mobius-logo-black-118x40@2x.png"
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/mobius-logo-muted-69x24@2x.png"
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/mobius-logo-square@2x.png"
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/mobius-logo-white-square-1200x1200@2x.png"

# Press kit versions
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/press-kit/mobius-logo-dark-rgb.png"
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/press-kit/mobius-logo-white-rgb.png"
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/press-kit/press-kit-mobius-logo-dark-preview-600x336@2x.png"
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/press-kit/press-kit-mobius-logo-white-preview-600x336@2x.png"

# Permanent versions
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/permanent/mobius-logo-email-dark-friendly-162x92@2x.png"
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/permanent/mobius-logo-blue-118x41@2x.png"

# Blog version
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/blog-mobius-logo-white-background-800x450@2x.png"

echo "Removing old Mobius logo files..."

# Remove any remaining Mobius logos
rm -f "$ASSETS_DIR/mobius-logo.svg"
rm -f "$ASSETS_DIR/mobius-logo-text-white.svg"

echo "Now I need to handle SVG conversions..."
echo "Note: SVG files need to be recreated as vector files for best quality."
echo "For now, replacing with PNG versions, but SVG versions should be created by a designer."

# For SVG files, we'll need to either:
# 1. Convert the PNG to SVG (lower quality)
# 2. Have a designer create proper SVG versions
# For now, let's create placeholder references

# Replace SVG references with PNG equivalents where possible
cp "$SOURCE_LOGO" "$ASSETS_DIR/mobius-logo.svg.png"
cp "$SOURCE_LOGO" "$ASSETS_DIR/mobius-logo-text-white.svg.png"
cp "$SOURCE_LOGO" "$ASSETS_DIR/mobius-logo-text-black.svg.png"
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/press-kit/mobius-logo-dark.svg.png"
cp "$SOURCE_LOGO" "$WEBSITE_ASSETS_DIR/press-kit/mobius-logo-white.svg.png"

echo "=== Logo replacement complete ==="
echo "Note: You may need to update file references in code from .svg to .png"
echo "Or have a designer create proper SVG versions of the new logo."
