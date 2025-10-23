package contract

import "github.com/notawar/mobius/mobius-server/server/mobius"

type ScimDetailsResponse struct {
	mobius.ScimDetails
	Err error `json:"-"`
}

func (r ScimDetailsResponse) Error() error {
	return r.Err
}
