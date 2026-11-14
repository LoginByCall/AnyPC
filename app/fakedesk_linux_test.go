package main

import "anypc/agent"

// Сессии настоящего агента в тестах app не трогают рабочий стол (zenity, wl-paste) того, кто их запускает.
func init() { agent.FakeDesktop() }
