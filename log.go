package main

import (
	"fmt"

	"go.uber.org/zap"
)

var logger *zap.Logger

func init() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		panic(fmt.Errorf("init zap logger failed: %v", err))
	}
}
