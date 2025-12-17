package branding

import "github.com/charmbracelet/lipgloss"

// Brand identity constants
const (
	AppName        = "Mobius"
	AppDescription = "Container Orchestration & MDM Platform"
	AppVersion     = "1.0.0"
)

// Color palette - Mobius brand colors (based on logo)
const (
	// Primary brand colors (from logo)
	ColorPrimary   = "#1c2f38" // Dark Blue - logo background, main brand color
	ColorSecondary = "#31413e" // Teal Blue - lighter areas, elevated surfaces
	ColorAccent    = "#d4af37" // Golden Yellow - logo accent, highlights, CTAs

	// Status colors (harmonized with brand palette)
	ColorSuccess = "#4ade80" // Green - success messages (lighter, modern)
	ColorError   = "#ef4444" // Red - error messages (softer than pure red)
	ColorWarning = "#fbbf24" // Amber - warning messages (complements gold)
	ColorInfo    = "#60a5fa" // Sky Blue - info messages (harmonizes with primary)

	// Neutral colors (optimized for dark theme)
	ColorTextPrimary   = "#ffffff" // Pure white - primary body text on dark bg
	ColorTextSecondary = "#94a3b8" // Slate Gray - secondary text, muted content
	ColorTextTertiary  = "#64748b" // Darker slate - tertiary text, subtle content
	ColorTextHeading   = "#d4af37" // Golden Yellow - headings (matches accent)
	ColorBackground    = "#1c2f38" // Dark Blue - main background (matches primary)
	ColorBackgroundAlt = "#31413e" // Teal Blue - alternate/elevated background
	ColorBorder        = "#334155" // Slate - borders, dividers
	ColorBorderLight   = "#475569" // Lighter slate - hover borders

	// Status indicator colors (for web/Tailwind - harmonized)
	ColorHealthy   = "#4ade80" // Green - healthy status (matches success)
	ColorUnhealthy = "#ef4444" // Red - unhealthy status (matches error)
	ColorDegraded  = "#fbbf24" // Amber - degraded status (matches warning)
)

// Typography
const (
	FontFamilyHeading = "Montserrat, sans-serif" // Light weight (300) for headings
	FontFamilyBody    = "Ubuntu, sans-serif"     // Regular text
	FontWeightLight   = "300"                    // Light - for Montserrat headings
	FontWeightNormal  = "400"                    // Normal - default
	FontWeightMedium  = "500"                    // Medium - emphasis
	FontWeightBold    = "700"                    // Bold - strong emphasis
	FontSizeSmall     = "0.875rem"               // 14px
	FontSizeBase      = "1rem"                   // 16px
	FontSizeLarge     = "1.25rem"                // 20px
	FontSizeXLarge    = "1.5rem"                 // 24px
	FontSize2XLarge   = "2rem"                   // 32px - large headings
)

// Spacing scale (rem units)
const (
	SpacingXS = "0.25rem" // 4px
	SpacingSM = "0.5rem"  // 8px
	SpacingMD = "1rem"    // 16px
	SpacingLG = "1.5rem"  // 24px
	SpacingXL = "2rem"    // 32px
)

// Border radius
const (
	BorderRadiusSmall  = "0.25rem" // 4px
	BorderRadiusMedium = "0.5rem"  // 8px
	BorderRadiusLarge  = "0.75rem" // 12px
	BorderRadiusFull   = "9999px"  // Fully rounded
)

// Asset paths (relative to project root)
const (
	LogoPath         = "assets/Mobius_Logo.png"
	LogoWithTextPath = "assets/Mobius-Logo-Text_1.png"
	FaviconSVGPath   = "assets/favicon.svg"
	FaviconICOPath   = "assets/favicon.ico"
	WallpaperPath    = "assets/mobius_wallpaper.png"
	Error404Path     = "assets/ERROR-404.png"
	ErrorGenericPath = "assets/ERROR-generic.png"
)

// Lipgloss style helpers for terminal UI
var (
	// Pre-built styles for common use cases
	StyleTitle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorAccent)). // Golden for headings
			Bold(true)

	StyleSuccess = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorSuccess)).
			Bold(true)

	StyleError = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorError)).
			Bold(true)

	StyleWarning = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorWarning)).
			Bold(true)

	StyleInfo = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorInfo))

	StyleSecondary = lipgloss.NewStyle().
			Foreground(lipgloss.Color(ColorTextSecondary))

	StyleBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(ColorAccent)). // Golden for borders
			Padding(1, 2)
)

// NewTitleStyle creates a centered title style with custom width
func NewTitleStyle(width int) lipgloss.Style {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(ColorAccent)). // Golden for headings
		Bold(true).
		Align(lipgloss.Center).
		Width(width)
}

// NewBoxStyle creates a styled box with custom width
func NewBoxStyle(width int) lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(ColorAccent)). // Golden for borders
		Padding(1, 2).
		Width(width)
}

// NewStatusStyle creates a status indicator style
func NewStatusStyle(status string) lipgloss.Style {
	var color string
	switch status {
	case "success", "healthy", "ready":
		color = ColorSuccess
	case "error", "failed", "unhealthy":
		color = ColorError
	case "warning", "degraded":
		color = ColorWarning
	default:
		color = ColorInfo
	}

	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(color)).
		Bold(true)
}

// Tailwind/CSS configuration generator
type TailwindTheme struct {
	Colors struct {
		Primary   string `json:"primary"`
		Secondary string `json:"secondary"`
		Accent    string `json:"accent"`
		Success   string `json:"success"`
		Error     string `json:"error"`
		Warning   string `json:"warning"`
		Info      string `json:"info"`
	} `json:"colors"`
	FontFamily struct {
		Heading string `json:"heading"`
		Body    string `json:"body"`
	} `json:"fontFamily"`
	FontWeight struct {
		Light  string `json:"light"`
		Normal string `json:"normal"`
		Medium string `json:"medium"`
		Bold   string `json:"bold"`
	} `json:"fontWeight"`
	Spacing struct {
		XS string `json:"xs"`
		SM string `json:"sm"`
		MD string `json:"md"`
		LG string `json:"lg"`
		XL string `json:"xl"`
	} `json:"spacing"`
	BorderRadius struct {
		SM string `json:"sm"`
		MD string `json:"md"`
		LG string `json:"lg"`
	} `json:"borderRadius"`
}

// GetTailwindTheme returns the theme configuration for Tailwind CSS
func GetTailwindTheme() TailwindTheme {
	theme := TailwindTheme{}
	theme.Colors.Primary = ColorPrimary
	theme.Colors.Secondary = ColorSecondary
	theme.Colors.Accent = ColorAccent
	theme.Colors.Success = ColorSuccess
	theme.Colors.Error = ColorError
	theme.Colors.Warning = ColorWarning
	theme.Colors.Info = ColorInfo
	theme.FontFamily.Heading = FontFamilyHeading
	theme.FontFamily.Body = FontFamilyBody
	theme.FontWeight.Light = FontWeightLight
	theme.FontWeight.Normal = FontWeightNormal
	theme.FontWeight.Medium = FontWeightMedium
	theme.FontWeight.Bold = FontWeightBold
	theme.Spacing.XS = SpacingXS
	theme.Spacing.SM = SpacingSM
	theme.Spacing.MD = SpacingMD
	theme.Spacing.LG = SpacingLG
	theme.Spacing.XL = SpacingXL
	theme.BorderRadius.SM = BorderRadiusSmall
	theme.BorderRadius.MD = BorderRadiusMedium
	theme.BorderRadius.LG = BorderRadiusLarge
	return theme
}
