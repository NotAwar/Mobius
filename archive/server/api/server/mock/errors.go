package mock

type Error struct {
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

// IsNotFound implements mobius.NotFoundError
func (e *Error) IsNotFound() bool {
	return true
}

// IsExists implements mobius.AlreadyExistsError
func (e *Error) IsExists() bool {
	return true
}
