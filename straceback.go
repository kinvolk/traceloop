package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/kinvolk/straceback/pkg/straceback"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(1)
	}
	cgroupPath := os.Args[1]

	t, err := straceback.NewTracer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	id, err := t.AddProg(cgroupPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Added prog id %v\n", id)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
	fmt.Printf("Interrupted!\n")
	_ = t.DumpProgWithQueue(id)
	err = t.DumpProg(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	t.Stop()
}
