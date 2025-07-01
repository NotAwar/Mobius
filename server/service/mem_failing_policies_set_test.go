package service

import (
	"testing"

	"github.com/notawar/mobius/v4/server/mobius/policytest"
)

func TestMemFailingPolicySet(t *testing.T) {
	m := NewMemFailingPolicySet()
	policytest.RunFailing1000hosts(t, m)
	m = NewMemFailingPolicySet()
	policytest.RunFailingBasic(t, m)
}
