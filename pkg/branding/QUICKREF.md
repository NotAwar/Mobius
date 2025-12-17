# Mobius Branding Quick Reference

This guide shows how to use the centralized branding system across all Mobius components.

## 🎨 Color Palette

**Based on Mobius Logo**

| Name | Hex | Usage |
|------|-----|-------|
| **Primary** | `#1c2f38` | Dark blue - logo background, main brand color |
| **Secondary** | `#31413e` | Teal blue - lighter areas, elevated surfaces |
| **Accent** | `#d4af37` | Golden yellow - logo accent, highlights, CTAs |
| **Success** | `#4ade80` | Green - success messages |
| **Error** | `#ef4444` | Red - error messages |
| **Warning** | `#fbbf24` | Amber - warning messages |
| **Info** | `#60a5fa` | Sky blue - info messages |
| **Healthy** | `#4ade80` | Green - service healthy |
| **Unhealthy** | `#ef4444` | Red - service down |
| **Degraded** | `#fbbf24` | Amber - service degraded |

## 📝 Go (Terminal UI)

### Import

```go
import "mobius/pkg/branding"
```

### Typography Constants

```go
// Font families
branding.FontFamilyHeading  // "Montserrat, sans-serif" - Light (300) for headings
branding.FontFamilyBody     // "Ubuntu, sans-serif" - Body text

// Font weights
branding.FontWeightLight    // "300" - Headings
branding.FontWeightNormal   // "400" - Default
branding.FontWeightMedium   // "500" - Emphasis
branding.FontWeightBold     // "700" - Strong

// Font sizes
branding.FontSizeSmall      // "0.875rem" (14px)
branding.FontSizeBase       // "1rem" (16px)
branding.FontSizeLarge      // "1.25rem" (20px)
branding.FontSizeXLarge     // "1.5rem" (24px)
branding.FontSize2XLarge    // "2rem" (32px)
```

### Pre-built Styles

```go
// Titles and headers
fmt.Println(branding.StyleTitle.Render("Mobius Server"))

// Status messages
fmt.Println(branding.StyleSuccess.Render("✓ Deployment successful"))
fmt.Println(branding.StyleError.Render("✗ Connection failed"))
fmt.Println(branding.StyleWarning.Render("⚠ Configuration incomplete"))
fmt.Println(branding.StyleInfo.Render("ℹ Server starting..."))

// Secondary text
fmt.Println(branding.StyleSecondary.Render("Press Ctrl+C to exit"))
```

### Custom Boxes

```go
// Create a styled box
box := branding.NewBoxStyle(60)
content := box.Render("Server is running\nPort: 3000")
fmt.Println(content)

// Custom title style
title := branding.NewTitleStyle(50)
fmt.Println(title.Render("⚙ Configuration"))
```

### Dynamic Status Styling

```go
// Status-based coloring
statusStyle := branding.NewStatusStyle("healthy")
fmt.Println(statusStyle.Render("● Cluster"))

statusStyle = branding.NewStatusStyle("error")
fmt.Println(statusStyle.Render("● Database"))
```

### Color Constants

```go
import "github.com/charmbracelet/lipgloss"

// Use raw color constants
myStyle := lipgloss.NewStyle().
    Foreground(lipgloss.Color(branding.ColorPrimary)).
    Background(lipgloss.Color(branding.ColorBackground))
```

## 🌐 TypeScript/Svelte (Web UI)

### Import

```typescript
import { theme, getStatusColor } from '$lib/theme';
```

### Colors in Templates

```svelte
<script lang="ts">
  import { theme } from '$lib/theme';
</script>

<!-- Use theme colors directly -->
<h1 style="color: {theme.colors.primary}">
  {theme.name}
</h1>

<!-- Status colors -->
<span style="color: {theme.colors.success}">✓ Connected</span>
<span style="color: {theme.colors.error}">✗ Failed</span>
```

### With Tailwind (Arbitrary Values)

```svelte
<!-- Primary button -->
<button class="bg-[#7D56F4] hover:bg-[#6B48D4] text-white px-4 py-2 rounded-lg">
  Deploy
</button>

<!-- Or use bg-purple-600 from Tailwind's built-in colors (similar) -->
<button class="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg">
  Deploy
</button>
```

### Status Helper

```typescript
import { getStatusColor } from '$lib/theme';

const color = getStatusColor('healthy'); // Returns #10B981
const errorColor = getStatusColor('error'); // Returns #FF0000
```

### Assets

```svelte
<!-- Logo -->
<img src={theme.assets.logo} alt="Mobius Logo" />

<!-- Favicon is already set in app.html -->
```

## 📦 Assets

All assets are available in:

- **Go**: `/assets/` directory (relative to project root)
- **Web**: `/static/assets/` directory (copied during build)

### Available Assets

```
assets/
├── Mobius_Logo.png           - Main logo (no text)
├── Mobius-Logo-Text_1.png    - Logo with text
├── favicon.svg                - SVG favicon
├── favicon.ico                - ICO favicon
├── mobius_wallpaper.png       - Background wallpaper
├── ERROR-404.png              - 404 error page
└── ERROR-generic.png          - Generic error page
```

### Usage in Go

```go
logoPath := branding.LogoPath // "assets/Mobius_Logo.png"
```

### Usage in Svelte

```svelte
<script>
  import { theme } from '$lib/theme';
</script>

<img src={theme.assets.logo} alt="Logo" />
```

## 🎯 Common Patterns

### Terminal: Success/Error Messages

```go
if err != nil {
    fmt.Println(branding.StyleError.Render("✗ " + err.Error()))
} else {
    fmt.Println(branding.StyleSuccess.Render("✓ Operation successful"))
}
```

### Web: Status Badges

```svelte
<span class="rounded-full px-2 py-1 text-sm
  {status === 'healthy' 
    ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
    : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'}">
  {status}
</span>
```

### Web: Health Indicator Dot

```svelte
<span class="h-2 w-2 rounded-full {healthy ? 'bg-green-500' : 'bg-red-500'}"></span>
```

## 🔄 Updating the Theme

To change colors across the entire application:

1. **Edit** `pkg/branding/branding.go` - Update constants
2. **Update** `pkg/branding/theme.json` - Keep JSON in sync
3. **Regenerate** `web/src/lib/theme.ts` - Copy new values
4. **Rebuild** - `go build` and restart web dev server

That's it! All UIs will use the new colors automatically.

## 📚 Documentation

- Full docs: `pkg/branding/README.md`
- Web dashboard: `web/README.md`
- Architecture: `docs/SERVER_ARCHITECTURE.md`
