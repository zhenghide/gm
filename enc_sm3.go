package main

import (
	"crypto/sm3"
	"fmt"
)

func main() {
	src := "abcdefg"
	h := sm3.New()
	h.Write([]byte(src))
	degist := h.Sum(nil)
	fmt.Println(degist)
	fmt.Println(len(degist))
	fmt.Println(string(degist))
}
