package main

import (
	"github.com/carbonetes/jacked/cmd/jacked/command"
	"github.com/carbonetes/jacked/internal/log"
)

func main() {
	if err := command.Run(); err != nil {
		log.Fatal(err)
	}
}
