//go:build !windows && !linux && !darwin

package main

import "log"

func main() { log.Fatal("AnyPC — Windows, Linux и macOS; сервер — ./server") }
