//go:build !windows

package main

import "log"

func main() { log.Fatal("AnyPC.exe — только Windows; сервер — ./server") }
