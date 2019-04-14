package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"

	"github.com/kinvolk/straceback/pkg/straceback"
)

var (
	serveHttp bool
	paths     []string
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "serve" {
		serveHttp = true
	} else {
		paths = os.Args[1:]
	}

	t, err := straceback.NewTracer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if serveHttp {
		addHandler := func(w http.ResponseWriter, r *http.Request) {
			cgroupPath := r.FormValue("cgrouppath")
			if cgroupPath == "" {
				fmt.Fprintf(w, "parameter cgrouppath missing\n")
				return
			}
			id, err := t.AddProg(cgroupPath)
			if err != nil {
				fmt.Fprintf(w, "%v\n", err)
				return
			}
			fmt.Fprintf(w, "added as id %v\n", id)
		}

		dumpHandler := func(w http.ResponseWriter, r *http.Request) {
			idStr := r.FormValue("id")
			if idStr == "" {
				fmt.Fprintf(w, "parameter id missing\n")
				return
			}
			id, err := strconv.Atoi(idStr)
			if err != nil {
				fmt.Fprintf(w, "%v\n", err)
				return
			}
			out, err := t.DumpProg(uint32(id))
			if err != nil {
				fmt.Fprintf(w, "%v\n", err)
				return
			}
			fmt.Fprintf(w, "%s", out)
		}

		http.HandleFunc("/add", addHandler)
		http.HandleFunc("/dump", dumpHandler)
		server := http.Server{}

		unixListener, err := net.Listen("unix", "/run/straceback.socket")
		if err != nil {
			panic(err)
		}
		server.Serve(unixListener)
	}

	var ids []uint32
	for _, cgroupPath := range paths {
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
		fmt.Printf("Dump with queue map:\n")
		_ = t.DumpProgWithQueue(id)
		fmt.Printf("Dump:\n")
		out, err := t.DumpProg(id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s", out)
	}

	t.Stop()
}
