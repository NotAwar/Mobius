# Static Assets

This directory contains static files served by SvelteKit at the root URL path.

## Assets Symlink

The `assets/` folder is a **symbolic link** to `/assets` (the project root assets directory).

```
web/static/assets -> ../../assets
```

### Why?

- **Single Source of Truth**: All logos, favicons, wallpapers, and error images are maintained in `/assets`
- **Shared Access**: Both Go code (via `pkg/branding`) and SvelteKit can reference the same files
- **No Duplication**: Prevents having multiple copies of assets that can get out of sync

### Usage in SvelteKit

Reference assets in your Svelte components like this:

```svelte
<!-- Favicon in app.html -->
<link rel="icon" href="%sveltekit.assets%/assets/favicon.svg" />

<!-- Images in components -->
<img src="/assets/Mobius_Logo.png" alt="Mobius Logo" />
<img src="/assets/mobius_wallpaper.png" alt="Wallpaper" />
```

### Usage in Go

Assets are referenced via the `pkg/branding` package:

```go
import "mobius/pkg/branding"

// Use the constants
logoPath := branding.LogoPath         // "assets/Mobius_Logo.png"
faviconPath := branding.FaviconSVGPath // "assets/favicon.svg"
```

## Available Assets

See `/assets/` directory for:

- `Mobius_Logo.png` - Main logo
- `Mobius-Logo-Text_1.png` - Logo with text
- `favicon.svg` - SVG favicon (preferred)
- `favicon.ico` - ICO favicon (fallback)
- `mobius_wallpaper.png` - Background wallpaper
- `ERROR-404.png` - 404 error page image
- `ERROR-generic.png` - Generic error page image

## robots.txt

The `robots.txt` file controls search engine crawler access. Modify as needed for your deployment.
