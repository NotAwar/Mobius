# Assets Directory

Centralized asset storage for the Mobius platform. This directory contains all logos, favicons, wallpapers, and error page images used across the application.

## Directory Structure

```
assets/
├── Mobius_Logo.png           # Main Mobius logo (PNG)
├── Mobius-Logo-Text_1.png    # Logo with text
├── favicon.svg               # SVG favicon (preferred for modern browsers)
├── favicon.ico               # ICO favicon (fallback for older browsers)
├── mobius_wallpaper.png      # Background wallpaper
├── ERROR-404.png             # 404 Not Found error page image
└── ERROR-generic.png         # Generic error page image
```

## Usage

### In Go Code

Reference assets via the `pkg/branding` package constants:

```go
import "mobius/pkg/branding"

// Asset paths
logoPath := branding.LogoPath              // "assets/Mobius_Logo.png"
logoWithText := branding.LogoWithTextPath  // "assets/Mobius-Logo-Text_1.png"
favicon := branding.FaviconSVGPath         // "assets/favicon.svg"
faviconICO := branding.FaviconICOPath      // "assets/favicon.ico"
wallpaper := branding.WallpaperPath        // "assets/mobius_wallpaper.png"
error404 := branding.Error404Path          // "assets/ERROR-404.png"
errorGeneric := branding.ErrorGenericPath  // "assets/ERROR-generic.png"
```

### In SvelteKit Web UI

Assets are accessible via a **symbolic link** at `/web/static/assets` → `/assets`:

```svelte
<!-- In app.html -->
<link rel="icon" href="%sveltekit.assets%/assets/favicon.svg" type="image/svg+xml" />
<link rel="alternate icon" href="%sveltekit.assets%/assets/favicon.ico" />

<!-- In Svelte components -->
<img src="/assets/Mobius_Logo.png" alt="Mobius Logo" />
<img src="/assets/mobius_wallpaper.png" alt="Wallpaper" />
```

See `/web/static/README.md` for more details on the symlink setup.

## Brand Colors

Assets use the official Mobius color palette (defined in `pkg/branding`):

- **Primary**: `#1c2f38` (Dark Blue) - Logo background
- **Secondary**: `#31413e` (Teal Blue) - Elevated surfaces
- **Accent**: `#d4af37` (Golden Yellow) - Logo accent, highlights

## Adding New Assets

1. Place new asset files in this `/assets` directory
2. Add path constants to `pkg/branding/branding.go` if needed:

   ```go
   const (
       NewAssetPath = "assets/new-asset.png"
   )
   ```

3. Assets automatically become available in both Go and SvelteKit
4. Commit assets to Git (they are tracked)

## Image Specifications

- **Logos**: PNG format, transparent background recommended
- **Favicons**:
  - SVG (preferred, scalable)
  - ICO (fallback, 16x16, 32x32, 48x48)
- **Wallpapers**: PNG/JPG, optimized for web (compress large images)
- **Error Images**: PNG format

## Maintenance

- Keep assets optimized for web delivery (compress large files)
- Maintain consistent naming: lowercase, hyphens for spaces
- Update `pkg/branding` constants when adding/removing assets
- Do not duplicate assets - this is the single source of truth
