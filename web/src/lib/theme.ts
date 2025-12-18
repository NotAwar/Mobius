/**
 * Mobius Brand Theme Configuration - Material Dark Theme
 * 
 * This file is the source of truth for all Mobius branding and styling.
 * Optimized for high contrast and readability in dark theme.
 */

export const theme = {
  name: 'Mobius',
  description: 'Container Orchestration & MDM Platform',
  version: '1.0.0',

  colors: {
    // Primary brand colors (matching mobiusdm.eu)
    primary: '#1c2f38',     // Dark Blue - main brand
    secondary: 'rgba(28, 47, 56, 0.95)', // Semi-transparent dark blue
    surface: '#1c2f38',     // Base surface
    surfaceVariant: 'rgba(28, 47, 56, 0.5)', // Lighter variant
    accent: '#d4af37',      // Golden Yellow - highlights, CTAs
    accentHover: '#e8c35a', // Brighter gold for hover states

    // Status colors (accessible on dark backgrounds)
    success: '#10b981',     // Green - success messages
    error: '#ef4444',       // Red - error messages
    warning: '#f59e0b',     // Amber - warning messages
    info: '#3b82f6',        // Blue - info messages

    // Health indicators
    healthy: '#10b981',     // Green - healthy status
    unhealthy: '#ef4444',   // Red - unhealthy status
    degraded: '#f59e0b',    // Amber - degraded status

    // Ivory/cream text colors (matching mobiusdm.eu)
    textPrimary: '#FFFFF0',     // Ivory - primary text
    textSecondary: '#FFFFF0',   // Ivory - secondary text
    textMuted: 'rgba(255, 255, 240, 0.7)', // Dimmed ivory
    textHeading: '#d4af37',     // Gold - headings
    
    // Layout colors
    background: '#1a252e',
    backgroundAlt: '#253744',
    border: '#334155',
    borderLight: '#475569',
    divider: '#1e293b',
  },

  typography: {
    fontFamily: {
      heading: 'Montserrat, sans-serif',  // Light weight (300) for headings
      body: 'Ubuntu, sans-serif',         // Regular text
    },
    fontWeight: {
      light: '300',   // Light - for Montserrat headings
      normal: '400',  // Normal - default
      medium: '500',  // Medium - emphasis
      bold: '700',    // Bold - strong emphasis
    },
    fontSize: {
      small: '0.875rem',   // 14px
      base: '1rem',        // 16px
      large: '1.25rem',    // 20px
      xlarge: '1.5rem',    // 24px
      '2xlarge': '2rem',   // 32px - large headings
    },
  },

  spacing: {
    xs: '0.25rem',  // 4px
    sm: '0.5rem',   // 8px
    md: '1rem',     // 16px
    lg: '1.5rem',   // 24px
    xl: '2rem',     // 32px
  },

  borderRadius: {
    small: '0.25rem',   // 4px
    medium: '0.5rem',   // 8px
    large: '0.75rem',   // 12px
    full: '9999px',     // Fully rounded
  },

  assets: {
    logo: '/assets/Mobius_Logo.png',
    logoWithText: '/assets/Mobius-Logo-Text_1.png',
    faviconSvg: '/assets/favicon.svg',
    faviconIco: '/assets/favicon.ico',
    wallpaper: '/assets/mobius_wallpaper.png',
    error404: '/assets/ERROR-404.png',
    errorGeneric: '/assets/ERROR-generic.png',
  },
} as const;

// Type-safe color keys
export type ColorKey = keyof typeof theme.colors;

// Helper function to get color by status
export function getStatusColor(status: 'success' | 'error' | 'warning' | 'info' | 'healthy' | 'unhealthy' | 'degraded'): string {
  return theme.colors[status];
}

// Tailwind class generators
export const tw = {
  // Primary button
  buttonPrimary: `rounded-lg bg-[${theme.colors.primary}] px-4 py-2 text-white transition hover:opacity-90`,
  
  // Secondary button
  buttonSecondary: `rounded-lg bg-[${theme.colors.accent}] px-4 py-2 text-white transition hover:opacity-90`,
  
  // Success badge
  badgeSuccess: `rounded-full px-2 py-1 text-sm font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300`,
  
  // Error badge
  badgeError: `rounded-full px-2 py-1 text-sm font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300`,
  
  // Card
  card: `rounded-lg bg-white p-6 shadow dark:bg-gray-800`,
  
  // Header
  header: `bg-white dark:bg-gray-800 shadow`,
} as const;
