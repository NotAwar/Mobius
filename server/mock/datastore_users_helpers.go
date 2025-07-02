package mock

import (
	"context"

	"github.com/notawar/mobius/server/mobius"
)

func UserByEmailWithUser(u *mobius.User) UserByEmailFunc {
	return func(ctx context.Context, email string) (*mobius.User, error) {
		return u, nil
	}
}

func UserWithEmailNotFound() UserByEmailFunc {
	return func(ctx context.Context, email string) (*mobius.User, error) {
		return nil, &Error{"not found"}
	}
}

func UserWithID(u *mobius.User) UserByIDFunc {
	return func(ctx context.Context, id uint) (*mobius.User, error) {
		return u, nil
	}
}
