package dep

import (
	"fmt"

	"github.com/notawar/mobius/v4/server/archtest/test_files/nesteddependency"
)

func init() {
	fmt.Println(nesteddependency.Item)
}
