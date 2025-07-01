package mdm

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"

	"github.com/smallstep/pkcs7"
)

var ProfileVariableRegex = regexp.MustCompile(`(\$MOBIUS_VAR_(?P<name1>\w+))|(\${MOBIUS_VAR_(?P<name2>\w+)})`)

// ProfileDataVariableRegex matches variables present in <data> section of Apple profile, which may cause validation issues.
var ProfileDataVariableRegex = regexp.MustCompile(`(\$MOBIUS_VAR_DIGICERT_DATA_(?P<name1>\w+))|(\${MOBIUS_VAR_DIGICERT_DATA_(?P<name2>\w+)})`)

// MaxProfileRetries is the maximum times an install profile command may be
// retried, after which marked as failed and no further attempts will be made
// to install the profile.
const MaxProfileRetries = 1

// DecryptBase64CMS decrypts a base64 encoded pkcs7-encrypted value using the
// provided certificate and private key.
func DecryptBase64CMS(p7Base64 string, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	p7Bytes, err := base64.StdEncoding.DecodeString(p7Base64)
	if err != nil {
		return nil, err
	}

	p7, err := pkcs7.Parse(p7Bytes)
	if err != nil {
		return nil, err
	}

	return p7.Decrypt(cert, key)
}

func prefixMatches(val []byte, prefix string) bool {
	return len(val) >= len(prefix) &&
		bytes.EqualFold([]byte(prefix), val[:len(prefix)])
}

// GetRawProfilePlatform identifies the platform type of a profile bytes by
// examining its initial content:
//
//   - Returns "darwin" if the profile starts with "<?xml", typical of Apple
//     platform profiles.
//   - Returns "windows" if the profile begins with "<replace" or "<add",
//   - Returns an empty string for profiles that are either unrecognized or
//     empty.
func GetRawProfilePlatform(profile []byte) string {
	trimmedProfile := bytes.TrimSpace(profile)

	if len(trimmedProfile) == 0 {
		return ""
	}

	if prefixMatches(trimmedProfile, "<?xml") || prefixMatches(trimmedProfile, `{`) {
		return "darwin"
	}

	if prefixMatches(trimmedProfile, "<replace") || prefixMatches(trimmedProfile, "<add") || prefixMatches(trimmedProfile, "<!--") {
		return "windows"
	}

	return ""
}

// GuessProfileExtension determines the likely file extension of a profile
// based on its content.
//
// It returns a string representing the determined file extension ("xml",
// "json", or "") based on the profile's content.
func GuessProfileExtension(profile []byte) string {
	trimmedProfile := bytes.TrimSpace(profile)

	switch {
	case prefixMatches(trimmedProfile, "<?xml"),
		prefixMatches(trimmedProfile, "<replace"),
		prefixMatches(trimmedProfile, "<add"):
		return "xml"
	case prefixMatches(trimmedProfile, "{"):
		return "json"
	default:
		return ""
	}
}

func EncryptAndEncode(plainText string, symmetricKey string) (string, error) {
	block, err := aes.NewCipher([]byte(symmetricKey))
	if err != nil {
		return "", fmt.Errorf("create new cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create new gcm: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	return base64.StdEncoding.EncodeToString(aesGCM.Seal(nonce, nonce, []byte(plainText), nil)), nil
}

func DecodeAndDecrypt(base64CipherText string, symmetricKey string) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(base64CipherText)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher([]byte(symmetricKey))
	if err != nil {
		return "", fmt.Errorf("create new cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create new gcm: %w", err)
	}

	// Get the nonce size
	nonceSize := aesGCM.NonceSize()

	// Extract the nonce from the encrypted data
	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]

	decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypting: %w", err)
	}

	return string(decrypted), nil
}

const (
	// MobiusdConfigProfileName is the value for the PayloadDisplayName used by
	// mobiusdaemon to read configuration values from the system.
	MobiusdConfigProfileName = "Mobiusd configuration"

	// MobiusCAConfigProfileName is the value for the PayloadDisplayName used by
	// mobiusdaemon to read configuration values from the system.
	MobiusCAConfigProfileName = "Mobius root certificate authority (CA)"

	// MobiusdFileVaultProfileName is the value for the PayloadDisplayName used
	// by Mobius to configure FileVault and FileVault Escrow.
	MobiusFileVaultProfileName = "Disk encryption"

	// MobiusWindowsOSUpdatesProfileName is the name of the profile used by Mobius
	// to configure Windows OS updates.
	MobiusWindowsOSUpdatesProfileName = "Windows OS Updates"

	// MobiusMacOSUpdatesProfileName is the name of the DDM profile used by Mobius
	// to configure macOS OS updates.
	MobiusMacOSUpdatesProfileName = "Mobius macOS OS Updates"

	// MobiusIOSUpdatesProfileName is the name of the DDM profile used by Mobius
	// to configure iOS OS updates.
	MobiusIOSUpdatesProfileName = "Mobius iOS OS Updates"

	// MobiusIPadOSUpdatesProfileName is the name of the DDM profile used by Mobius
	// to configure iPadOS OS updates.
	MobiusIPadOSUpdatesProfileName = "Mobius iPadOS OS Updates"
)

// MobiusReservedProfileNames returns a map of PayloadDisplayName or profile
// name strings that are reserved by Mobius.
func MobiusReservedProfileNames() map[string]struct{} {
	return map[string]struct{}{
		MobiusdConfigProfileName:          {},
		MobiusFileVaultProfileName:        {},
		MobiusWindowsOSUpdatesProfileName: {},
		MobiusMacOSUpdatesProfileName:     {},
		MobiusIOSUpdatesProfileName:       {},
		MobiusIPadOSUpdatesProfileName:    {},
		MobiusCAConfigProfileName:         {},
	}
}

// ListMobiusReservedWindowsProfileNames returns a list of PayloadDisplayName strings
// that are reserved by Mobius for Windows.
func ListMobiusReservedWindowsProfileNames() []string {
	return []string{MobiusWindowsOSUpdatesProfileName}
}

// ListMobiusReservedMacOSProfileNames returns a list of PayloadDisplayName strings
// that are reserved by Mobius for macOS.
func ListMobiusReservedMacOSProfileNames() []string {
	return []string{MobiusFileVaultProfileName, MobiusdConfigProfileName, MobiusCAConfigProfileName}
}

// ListMobiusReservedMacOSDeclarationNames returns a list of declaration names
// that are reserved by Mobius for Apple DDM declarations.
func ListMobiusReservedMacOSDeclarationNames() []string {
	return []string{
		MobiusMacOSUpdatesProfileName,
		MobiusIOSUpdatesProfileName,
		MobiusIPadOSUpdatesProfileName,
	}
}
