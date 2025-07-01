package cached_mysql

import (
	"encoding/json"

	"github.com/notawar/mobius/v4/server/mobius"
)

type packsList []*mobius.Pack

func (pl packsList) Clone() (mobius.Cloner, error) {
	var cloned packsList
	if pl == nil {
		return cloned, nil
	}

	cloned = make(packsList, 0, len(pl))
	for _, p := range pl {
		cloned = append(cloned, p.Copy())
	}
	return cloned, nil
}

type rawJSONMessage json.RawMessage

func (r *rawJSONMessage) Clone() (mobius.Cloner, error) {
	var clone *rawJSONMessage
	if r == nil {
		return clone, nil
	}

	msg := make(rawJSONMessage, len(*r))
	copy(msg, *r)
	return &msg, nil
}

type integer int

func (i integer) Clone() (mobius.Cloner, error) {
	return i, nil
}
