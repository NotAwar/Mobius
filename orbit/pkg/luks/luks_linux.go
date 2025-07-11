//go:build linux

package luks

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver"
	"github.com/notawar/mobius/orbit/pkg/dialog"
	"github.com/notawar/mobius/orbit/pkg/kdialog"
	"github.com/notawar/mobius/orbit/pkg/lvm"
	"github.com/notawar/mobius/orbit/pkg/zenity"
	"github.com/notawar/mobius/server/mobius"
	"github.com/rs/zerolog/log"
	"github.com/siderolabs/go-blockdevice/v2/encryption"
	luksdevice "github.com/siderolabs/go-blockdevice/v2/encryption/luks"
)

const (
	entryDialogTitle     = "Enter disk encryption passphrase"
	entryDialogText      = "Passphrase:"
	retryEntryDialogText = "Passphrase incorrect. Please try again."
	infoTitle            = "Disk encryption"
	infoFailedText       = "Failed to escrow key. Please try again later."
	infoSuccessText      = "Disk encryption key created! Now, return to your browser window and follow the instructions to verify."
	timeoutMessage       = "Please visit Mobius Desktop > My device and click Create key"
	maxKeySlots          = 8
	userKeySlot          = 0 // Key slot 0 is assumed to be the location of the user's passphrase
)

var ErrKeySlotFull = regexp.MustCompile(`Key slot \d+ is full`)

func isInstalled(toolName string) bool {
	path, err := exec.LookPath(toolName)
	if err != nil {
		return false
	}
	return path != ""
}

func (lr *LuksRunner) Run(oc *mobius.OrbitConfig) error {
	ctx := context.Background()

	if !oc.Notifications.RunDiskEncryptionEscrow {
		return nil
	}

	if !isInstalled("cryptsetup") {
		return errors.New("cryptsetup is not installed")
	}

	switch {
	case isInstalled("zenity"):
		lr.notifier = zenity.New()
	case isInstalled("kdialog"):
		lr.notifier = kdialog.New()
	default:
		return errors.New("No supported dialog tool found")
	}

	devicePath, err := lvm.FindRootDisk()
	if err != nil {
		return fmt.Errorf("Failed to find LUKS Root Partition: %w", err)
	}

	var response LuksResponse
	key, keyslot, err := lr.getEscrowKey(ctx, devicePath)
	if err != nil {
		response.Err = err.Error()
	}

	if len(key) == 0 && err == nil {
		// dialog was canceled or timed out
		return nil
	}

	response.Passphrase = string(key)
	response.KeySlot = keyslot

	if keyslot != nil {
		salt, err := getSaltforKeySlot(ctx, devicePath, *keyslot)
		if err != nil {
			if err := removeKeySlot(ctx, devicePath, *keyslot); err != nil {
				log.Error().Err(err).Msgf("failed to remove key slot %d", *keyslot)
			}
			response.Err = fmt.Sprintf("Failed to get salt for key slot: %s", err)
		}
		response.Salt = salt
	}

	if err := lr.escrower.SendLinuxKeyEscrowResponse(response); err != nil {
		// If sending the response fails, remove the key slot
		if keyslot != nil {
			if err := removeKeySlot(ctx, devicePath, *keyslot); err != nil {
				log.Error().Err(err).Msg("failed to remove key slot")
			}
		}

		// Show error in dialog
		if err := lr.infoPrompt(infoTitle, infoFailedText); err != nil {
			log.Info().Err(err).Msg("failed to show failed escrow key dialog")
		}

		return fmt.Errorf("escrower escrowKey err: %w", err)
	}

	if response.Err != "" {
		if err := lr.infoPrompt(infoTitle, response.Err); err != nil {
			log.Info().Err(err).Msg("failed to show response error dialog")
		}
		return fmt.Errorf("error getting linux escrow key: %s", response.Err)
	}

	// Show success dialog
	if err := lr.infoPrompt(infoTitle, infoSuccessText); err != nil {
		log.Info().Err(err).Msg("failed to show success escrow key dialog")
	}

	return nil
}

func (lr *LuksRunner) getEscrowKey(ctx context.Context, devicePath string) ([]byte, *uint, error) {
	// AESXTSPlain64Cipher is the default cipher used by ubuntu/kubuntu/fedora
	device := luksdevice.New(luksdevice.AESXTSPlain64Cipher)

	// Prompt user for existing LUKS passphrase
	passphrase, err := lr.entryPrompt(ctx, entryDialogTitle, entryDialogText)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to show passphrase entry prompt: %w", err)
	}

	if len(passphrase) == 0 {
		log.Debug().Msg("Passphrase is empty, no password supplied, dialog was canceled, or timed out")
		return nil, nil, nil
	}

	// Validate the passphrase
	for {
		log.Debug().Msg("Validating disk passphrase")
		valid, err := lr.passphraseIsValid(ctx, device, devicePath, passphrase, userKeySlot)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed validating passphrase: %w", err)
		}

		if valid {
			break
		}

		passphrase, err = lr.entryPrompt(ctx, entryDialogTitle, retryEntryDialogText)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed re-prompting for passphrase: %w", err)
		}

		if len(passphrase) == 0 {
			log.Debug().Msg("Passphrase is empty, no password supplied, dialog was canceled, or timed out")
			return nil, nil, nil
		}

	}

	log.Debug().Msg("Generating random disk encryption passphrase")
	escrowPassphrase, err := generateRandomPassphrase()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate random passphrase: %w", err)
	}

	log.Debug().Msg("Getting the next available keyslot")
	keySlot, err := getNextAvailableKeySlot(ctx, devicePath)
	if err != nil {
		return nil, nil, fmt.Errorf("finding available keyslot: %w", err)
	}
	log.Debug().Msgf("Found available keyslot: %d", keySlot)

	userKey := encryption.NewKey(userKeySlot, passphrase)
	escrowKey := encryption.NewKey(int(keySlot), escrowPassphrase) // #nosec G115

	if err := device.AddKey(ctx, devicePath, userKey, escrowKey); err != nil {
		return nil, nil, fmt.Errorf("Failed to add key: %w", err)
	}

	log.Debug().Msg("Validating newly inserted key")
	valid, err := lr.passphraseIsValid(ctx, device, devicePath, escrowPassphrase, keySlot)
	if err != nil {
		return nil, nil, fmt.Errorf("Error while validating escrow passphrase: %w", err)
	}

	if !valid {
		return nil, nil, errors.New("Failed to validate escrow passphrase")
	}

	return escrowPassphrase, &keySlot, nil
}

func (lr *LuksRunner) passphraseIsValid(ctx context.Context, device *luksdevice.LUKS, devicePath string, passphrase []byte, keyslot uint) (bool, error) {
	if len(passphrase) == 0 {
		return false, nil
	}

	valid, err := device.CheckKey(ctx, devicePath, encryption.NewKey(int(keyslot), passphrase)) // #nosec G115
	if err != nil {
		return false, fmt.Errorf("Error validating passphrase: %w", err)
	}

	return valid, nil
}

func getNextAvailableKeySlot(ctx context.Context, devicePath string) (uint, error) {
	dump, err := GetLuksDump(ctx, devicePath)
	if err != nil {
		return 0, fmt.Errorf("get next available key slot: %w", err)
	}

	keysTaken := []uint32{}

	for keyStr := range dump.Keyslots {
		key, err := strconv.ParseUint(keyStr, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse next available key slot: %w", err)
		}
		keysTaken = append(keysTaken, uint32(key))
	}

	sort.Slice(keysTaken, func(i, j int) bool {
		return keysTaken[i] < keysTaken[j]
	})

	// Check for gaps in keys in case one was deleted
	var unusedKey uint32
	for _, keySlot := range keysTaken {
		if unusedKey == keySlot {
			unusedKey++
		}
	}

	if unusedKey >= maxKeySlots {
		return 0, fmt.Errorf("no empty key slots available: %d", unusedKey)
	}

	return uint(unusedKey), nil
}

// generateRandomPassphrase generates a random passphrase with 32 characters
// in the format XXXX-XXXX-XXXX-XXXX where X is a random character from the
// set [0-9A-Za-z].
func generateRandomPassphrase() ([]byte, error) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const length = 35 // 32 characters + 3 dashes
	passphrase := make([]byte, length)

	for i := 0; i < length; i++ {
		// Insert dashes at positions 8, 17, and 26
		if i == 8 || i == 17 || i == 26 {
			passphrase[i] = '-'
			continue
		}

		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return nil, err
		}
		passphrase[i] = chars[num.Int64()]
	}

	return passphrase, nil
}

func (lr *LuksRunner) entryPrompt(ctx context.Context, title, text string) ([]byte, error) {
	passphrase, err := lr.notifier.ShowEntry(dialog.EntryOptions{
		Title:    title,
		Text:     text,
		HideText: true,
		TimeOut:  1 * time.Minute,
	})
	if err != nil {
		switch {
		case errors.Is(err, dialog.ErrCanceled):
			log.Debug().Msg("end user canceled key escrow dialog")
			return nil, nil
		case errors.Is(err, dialog.ErrTimeout):
			log.Debug().Msg("key escrow dialog timed out")
			err := lr.infoPrompt(infoTitle, timeoutMessage)
			if err != nil {
				log.Info().Err(err).Msg("failed to show timeout dialog")
			}
			return nil, nil
		case errors.Is(err, dialog.ErrUnknown):
			return nil, err
		default:
			return nil, err
		}
	}

	return passphrase, nil
}

func (lr *LuksRunner) infoPrompt(title, text string) error {
	err := lr.notifier.ShowInfo(dialog.InfoOptions{
		Title:   title,
		Text:    text,
		TimeOut: 1 * time.Minute,
	})
	if err != nil {
		switch {
		case errors.Is(err, dialog.ErrTimeout):
			log.Debug().Msg("successPrompt timed out")
			return nil
		default:
			return err
		}
	}

	return nil
}

func GetLuksDump(ctx context.Context, devicePath string) (*LuksDump, error) {
	var jsonFlag string
	var jsonNeedsExtraction bool

	lessThan2_4, err := isCryptsetupVersionLessThan2_4()
	if err != nil {
		return nil, fmt.Errorf("Failed to check cryptsetup version: %w", err)
	}

	if lessThan2_4 {
		jsonFlag = "--debug-json"
		jsonNeedsExtraction = true
	} else {
		jsonFlag = "--dump-json-metadata"
	}

	cmd := exec.CommandContext(ctx, "cryptsetup", "luksDump", jsonFlag, devicePath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Failed to run cryptsetup luksDump: %w", err)
	}

	if jsonNeedsExtraction {
		output, err = extractJSON(output)
		if err != nil {
			return nil, fmt.Errorf("Failed to extract JSON from cryptsetup luksDump output: %w", err)
		}
	}

	var dump LuksDump
	if err := json.Unmarshal(output, &dump); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal luksDump output: %w", err)
	}

	return &dump, nil
}

func getSaltforKeySlot(ctx context.Context, devicePath string, keySlot uint) (string, error) {
	dump, err := GetLuksDump(ctx, devicePath)
	if err != nil {
		return "", fmt.Errorf("getting salt for key slot: %w", err)
	}

	slot, ok := dump.Keyslots[fmt.Sprintf("%d", keySlot)]
	if !ok {
		return "", errors.New("key slot not found")
	}

	return slot.KDF.Salt, nil
}

func removeKeySlot(ctx context.Context, devicePath string, keySlot uint) error {
	cmd := exec.CommandContext(ctx, "cryptsetup", "luksKillSlot", devicePath, fmt.Sprintf("%d", keySlot)) // #nosec G204
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Failed to run cryptsetup luksKillSlot: %w", err)
	}

	return nil
}

// isCryptsetupVersionLessThan2_4 checks if the installed cryptsetup version is less than 2.4.0
func isCryptsetupVersionLessThan2_4() (bool, error) {
	cmd := exec.Command("cryptsetup", "--version")
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("failed to run cryptsetup: %w", err)
	}

	// Parse the output
	// Examples of output:
	// "cryptsetup 2.7.0 flags: UDEV BLKID KEYRING FIPS KERNEL_CAPI HW_OPAL"
	// "cryptsetup 2.2.2"
	outputStr := strings.TrimSpace(string(output))
	parts := strings.Fields(outputStr)

	// The second field should always contain the version number
	if len(parts) < 2 {
		return false, fmt.Errorf("unexpected output format: %s", outputStr)
	}

	installedVersion, err := semver.NewVersion(parts[1])
	if err != nil {
		return false, fmt.Errorf("failed to parse version: %w", err)
	}

	// Compare against version 2.4.0
	targetVersion := semver.MustParse("2.4.0")
	return installedVersion.LessThan(targetVersion), nil
}
