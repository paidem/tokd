// tokd: single-user token store for AI agents. See README.md.
package main

import (
	"log"
	_ "time/tzdata" // distroless has no zoneinfo; TZ=Europe/Berlin etc. still works

	"github.com/paidem/tokd/internal/server"
)

func main() {
	s, err := server.New(server.ConfigFromEnv())
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(s.ListenAndServe())
}
