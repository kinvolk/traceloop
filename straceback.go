package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/kinvolk/straceback/pkg/straceback"
)

func main() {
	t, err := straceback.NewTracer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	var ids []uint32
	for _, cgroupPath := range os.Args[1:] {
		id, err := t.AddProg(cgroupPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Added cgroup %q as id %v\n", cgroupPath, id)
		ids = append(ids, id)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
	fmt.Printf("Interrupted!\n")

	for _, id := range ids {
		_ = t.DumpProgWithQueue(id)
		err = t.DumpProg(id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}

	t.Stop()
}
