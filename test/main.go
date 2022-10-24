package main

import (
	"fmt"
	"os/user"
)

func main() {
	u, _ := user.LookupId("1000")
	fmt.Printf("%+v", u)
}
