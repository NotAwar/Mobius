package nesteddependency

import "fmt"
import "github.com/notawar/mobius/v4/server/archtest/test_files/transative"

const Item = "depend on me"

func SomeMethod() {
	fmt.Println(transative.NowYouDependOnMe)
}
