package dep

import (
	"fmt"

	"github.com/notawar/mobius/server/archtest/test_files/nesteddependency"
)

func init() {
	fmt.Println(nesteddependency.Item)
}
