# Mobius Branding Package

Centralized branding and theming system for all Mobius user interfaces.

## Overview

This package provides a single source of truth for:

- **Colors**: Brand colors, status colors, and semantic colors
- **Typography**: Font families, sizes, and weights
- **Spacing**: Consistent spacing scale across all UIs
- **Assets**: Logos, icons, and images
- **Styles**: Pre-built lipgloss styles for terminal UI

## Usage

### Go (Terminal UI / Lipgloss)

```go
import "mobius/pkg/branding"

// Use pre-built styles
fmt.Println(branding.StyleTitle.Render("Mobius Server"))
fmt.Println(branding.StyleSuccess.Render("✓ Deployment successful"))
fmt.Println(branding.StyleError.Render("✗ Connection failed"))

// Create custom styled box
box := branding.NewBoxStyle(60)
content := box.Render("Server is running on port 3000")
fmt.Println(content)

// Use color constants
myStyle := lipgloss.NewStyle().
    Foreground(lipgloss.Color(branding.ColorPrimary)).
    Background(lipgloss.Color(branding.ColorBackground))
```

### TypeScript/Svelte (Web UI)

```typescript
import { theme, getStatusColor } from '$lib/theme';

// Use color constants
const primaryColor = theme.colors.primary;
const healthyColor = getStatusColor('healthy');

// Use in components
<div style="color: {theme.colors.primary}">
  {theme.name}
</div>

// Or with Tailwind (use arbitrary values)
<button class="bg-[{theme.colors.primary}] text-white rounded-lg px-4 py-2">
  Click me
</button>
```

### JSON Configuration

The `theme.json` file can be imported by build tools, documentation generators, or other systems:

```json
{
  "colors": {
    "primary": "#7D56F4",
    "secondary": "#04B575",
    ...
  }
}
```

## Color Palette

**Based on Mobius Logo Design**

### Brand Colors

- **Primary** (`#1c2f38`): Dark blue from logo background - Main brand color, used for backgrounds, headers
- **Secondary** (`#31413e`): Teal blue - Lighter areas, elevated surfaces, cards
- **Accent** (`#d4af37`): Golden yellow from logo - Highlights, CTAs, important actions

### Status Colors (Harmonized with Brand)

- **Success** (`#4ade80`): Green - Successful operations
- **Error** (`#ef4444`): Red - Errors and failures
- **Warning** (`#fbbf24`): Amber - Warnings and cautions (complements gold accent)
- **Info** (`#60a5fa`): Sky blue - Informational messages

### Health Indicators

- **Healthy** (`#4ade80`): Services running normally
- **Unhealthy** (`#ef4444`): Services down or failing
- **Degraded** (`#fbbf24`): Services running with issues

## Typography

**Font Families:**

- **Headings**: Montserrat (Light weight 300) - Modern, clean geometric sans-serif
- **Body**: Ubuntu - Readable, friendly sans-serif optimized for screens

**Font Weights:**

- Light (300) - Headings (Montserrat)
- Normal (400) - Body text, default
- Medium (500) - Emphasis, buttons, interactive elements
- Bold (700) - Strong emphasis

**Font Sizes:**

- Small: 14px (0.875rem)
- Base: 16px (1rem)
- Large: 20px (1.25rem)
- XLarge: 24px (1.5rem)
- 2XLarge: 32px (2rem) - Large headings

## Assets

All assets are located in `/assets` directory:

- `Mobius_Logo.png` - Main logo
- `Mobius-Logo-Text_1.png` - Logo with text
- `favicon.svg` / `favicon.ico` - Browser favicon
- `mobius_wallpaper.png` - Background wallpaper
- `ERROR-404.png` / `ERROR-generic.png` - Error pages

## Updating the Theme

To change branding across the entire application:

1. **Edit this file**: `pkg/branding/branding.go`
   - Update color constants
   - Modify typography settings
   - Adjust spacing/borders

2. **Update JSON**: `pkg/branding/theme.json`
   - Keep in sync with Go constants
   - Used for tooling integration

3. **Regenerate TypeScript**: `web/src/lib/theme.ts`
   - Copy values from theme.json
   - Ensures web UI matches

4. **Test all UIs**:
   - Terminal UI (TUI)
   - Lipgloss authentication
   - Svelte web dashboard

## Philosophy

**Single Source of Truth**: All UIs should reference this package rather than hardcoding colors or styles.

**Consistency**: Changes here propagate to all user interfaces automatically.

**Flexibility**: Easily rebrand the entire application by editing one place.

## Examples

See how the theme is used:

- `cmd/server/main.go` - Lipgloss authentication box
- `internal/tui/tui.go` - Terminal UI styles
- `web/src/routes/+page.svelte` - Dashboard with brand colors
