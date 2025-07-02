package main

import (
	"fmt"

	"github.com/notawar/mobius/orbit/pkg/lvm"
)

func main() {
	disk, err := lvm.FindRootDisk()
	if err != nil {
		panic(err)
	}
	fmt.Println("Root Partition:", disk)
}
