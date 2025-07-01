//go:build !darwin

package profiles

import "github.com/notawar/mobius/v4/server/mobius"

func GetMobiusdConfig() (*mobius.MDMAppleMobiusdConfig, error) {
	return nil, ErrNotImplemented
}

func IsEnrolledInMDM() (bool, string, error) {
	return false, "", ErrNotImplemented
}

func CheckAssignedEnrollmentProfile(expectedURL string) error {
	return ErrNotImplemented
}

func GetCustomEnrollmentProfileEndUserEmail() (string, error) {
	return "", ErrNotImplemented
}
