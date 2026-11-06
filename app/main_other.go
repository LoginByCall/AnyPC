//go:build !windows && !linux

package main

import "log"

func main() { log.Fatal("AnyPC — Windows и Linux; сервер — ./server") }
