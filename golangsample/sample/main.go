package main

import "fmt"

//go:noinline
func Uprobe(a, b, c, d, e, f, g int) (h, i int) {
	h = a + b + c + d
	i = e + f + g
	return
}

func main() {
	h, i := Uprobe(1, 2, 3, 4, 5, 6, 7)
	fmt.Println(h, i)
}
