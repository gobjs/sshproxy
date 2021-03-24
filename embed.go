package main

import (
	_ "embed"
)

//go:embed server.key
var serverKeyPem []byte
