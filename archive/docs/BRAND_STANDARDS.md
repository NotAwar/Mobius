# Mobius MDM Brand Standards

This document defines the visual identity standards for Mobius MDM across all platforms and communications.

## Color Palette

### Primary Colors

#### Deep Blue

- **Hex**: `#1c2f38`
- **Usage**: Primary text, headings, main UI elements, navigation
- **CSS Variable**: `--mobius-blue`

#### Gold

- **Hex**: `#d4af37`
- **Usage**: Call-to-action buttons, links, highlights, accents
- **CSS Variable**: `--mobius-gold`
- **Hover State**: `#b89530` (darker gold)

### Supporting Colors

#### Light Background

- **Hex**: `#f9fafc`
- **Usage**: Page backgrounds, card backgrounds

#### Border Gray

- **Hex**: `#e2e4ea`
- **Usage**: Borders, dividers, subtle separations

#### Secondary Text

- **Hex**: `#515774`
- **Usage**: Secondary text, captions, helper text

## Typography

### Headings

- **Font Family**: Montserrat
- **Weights**: 400 (Regular), 600 (Semi-Bold), 700 (Bold)
- **Usage**: All heading levels (h1-h6), page titles, section headers
- **CDN**: `https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&display=swap`

### Body Text

- **Font Family**: Inter
- **Weights**: 400 (Regular), 500 (Medium), 600 (Semi-Bold)
- **Usage**: Paragraphs, lists, form labels, UI text
- **CDN**: `https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap`

## Email Templates

All email templates should follow these standards:

### Structure

```html
<head>
  <link rel="preconnect" href="https://fonts.gstatic.com" />
  <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet" />
  <style>
    body {
      font-family: "Inter", sans-serif;
      color: #1c2f38;
    }
    h1, h2, h3, h4, h5, h6 {
      font-family: "Montserrat", sans-serif;
      color: #1c2f38;
    }
    a {
      color: #d4af37;
    }
    a:hover {
      color: #b89530;
    }
  </style>
</head>
```

### Call-to-Action Buttons

```html
<a href="[URL]" target="_blank" style="
  font-weight: 700;
  color: #1c2f38;
  text-decoration: none;
  border-radius: 4px;
  background-color: #d4af37;
  border-top: 8px solid #d4af37;
  border-bottom: 8px solid #d4af37;
  border-right: 16px solid #d4af37;
  border-left: 16px solid #d4af37;
  display: inline-block;
">
  Button Text
</a>
```

## Web UI (Svelte)

### CSS Variables

Add these to your root CSS:

```css
:root {
  /* Primary Colors */
  --mobius-blue: #1c2f38;
  --mobius-gold: #d4af37;
  --mobius-gold-hover: #b89530;
  
  /* Supporting Colors */
  --mobius-bg-light: #f9fafc;
  --mobius-border-gray: #e2e4ea;
  --mobius-text-secondary: #515774;
  
  /* Typography */
  --font-heading: 'Montserrat', sans-serif;
  --font-body: 'Inter', sans-serif;
}
```

### Component Styles

#### Headings

```svelte
<h1 style="font-family: var(--font-heading); color: var(--mobius-blue);">
  Page Title
</h1>
```

#### Primary Button

```svelte
<button style="
  background-color: var(--mobius-gold);
  color: var(--mobius-blue);
  font-weight: 600;
  border: none;
  border-radius: 4px;
  padding: 8px 16px;
">
  Action
</button>
```

#### Links

```svelte
<a href="#" style="color: var(--mobius-gold);">
  Learn more
</a>
```

## Documentation

### Markdown Styling

When creating documentation:

- Use clear heading hierarchy (H1 for title, H2 for sections, H3 for subsections)
- Code blocks should use appropriate language tags
- Use tables for structured data
- Include visual examples when possible

## Accessibility

### Color Contrast

- Ensure all text meets WCAG AA standards (4.5:1 for normal text, 3:1 for large text)
- Blue (`#1c2f38`) on white background: ✅ Passes
- Gold (`#d4af37`) on blue background: ✅ Passes
- Gold (`#d4af37`) on white background: Use for buttons with dark text, not text alone

### Font Sizes

- Minimum body text: 16px
- Minimum secondary text: 14px
- Headings: Scale appropriately (24px for H1, 20px for H2, etc.)

## Logo Usage

### Email Logo

- Use appropriate logo variant based on background
- Maintain aspect ratio
- Minimum size: 162x92px (displayed size), 324x184px (2x for retina)

### Social Media Icons

- Use monochrome icons with consistent sizing
- Size: 20x20px displayed, 40x40px @ 2x
- Spacing: 20px padding-right between icons

## Implementation Checklist

When creating new branded materials:

- [ ] Headings use Montserrat font
- [ ] Body text uses Inter font
- [ ] Primary blue (#1c2f38) used for main text and headings
- [ ] Gold (#d4af37) used for CTAs and accent elements
- [ ] Hover states implemented for interactive elements
- [ ] Responsive design tested on mobile devices
- [ ] Accessibility contrast ratios verified
- [ ] Logo properly sized and positioned

## Examples

### Updated Templates

- ✅ `server/mail/templates/invite_token.html` - Implements all brand standards

### Templates To Update

- [ ] `server/mail/templates/change_email_confirmation.html`
- [ ] `server/mail/templates/mfa.html`
- [ ] `server/mail/templates/password_reset.html`
- [ ] `server/mail/templates/smtp_setup.html`

### Frontend Components

- [ ] Update Svelte components to use brand colors
- [ ] Implement CSS variables in main stylesheet
- [ ] Update component library documentation

## Version History

- **v1.0** (October 23, 2025) - Initial brand standards document
  - Defined primary colors: Blue (#1c2f38) and Gold (#d4af37)
  - Established typography: Montserrat for headings, Inter for body
  - Created email template standards
  - Documented CSS implementation patterns
