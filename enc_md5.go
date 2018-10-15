package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	src := "abcde"
	h := md5.New()
	h.Write([]byte(src))
	degist := h.Sum(nil)
	fmt.Println(degist)
	fmt.Println(len(degist))
	fmt.Println(string(degist))

	d := md5.New()
	d.Write(degist)
	s := d.Sum(nil)
	fmt.Println(s)
	fmt.Println(len(s))
	fmt.Println(string(s))

}
