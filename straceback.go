package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"

	"github.com/kinvolk/straceback/pkg/straceback"
)

func main() {
	if len(os.Args) != 3 {
		os.Exit(1)
	}
	cgroupPath := os.Args[1]
	cgroupId, err := strconv.ParseUint(os.Args[2], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	t, err := straceback.NewTracer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	id, err := t.AddProg(cgroupPath, cgroupId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Added prog id %v\n", id)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
	fmt.Printf("Interrupted!\n")
	_ = t.ShortDumpProg(id)
	err = t.DumpProg(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	t.Stop()
}
