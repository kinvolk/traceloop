package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/kinvolk/traceloop/pkg/straceback"
)

var (
	serveHttp bool
	withPidns bool
	paths     []string
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "k8s" {
		withPidns = true
		serveHttp = true
	}

	if len(os.Args) == 2 && os.Args[1] == "guess" {
		withPidns = true
	}

	if len(os.Args) == 2 && os.Args[1] == "serve" {
		serveHttp = true
	} else {
		paths = os.Args[1:]
	}

	t, err := straceback.NewTracer(withPidns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if withPidns && !serveHttp {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, os.Kill)
		select {
		case <-sig:
			fmt.Printf("Interrupted!\n")
			break
		}
		t.DumpAll()
		os.Exit(0)
	}

	if serveHttp {
		listHandler := func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s", t.List())
		}
		addHandler := func(w http.ResponseWriter, r *http.Request) {
			cgroupPath := r.FormValue("cgrouppath")
			if cgroupPath == "" {
				fmt.Fprintf(w, "parameter cgrouppath missing\n")
				return
			}
			name := r.FormValue("name") // name is optional
			id, err := t.AddProg(cgroupPath, name)
			if err != nil {
				fmt.Fprintf(w, "%v\n", err)
				return
			}
			fmt.Fprintf(w, "added as id %v\n", id)
		}

		dumpByNameHandler := func(w http.ResponseWriter, r *http.Request) {
			nameStr := r.FormValue("name")
			out, err := t.DumpProgByName(nameStr)
			if err != nil {
				fmt.Fprintf(w, "%v\n", err)
				return
			}
			fmt.Fprintf(w, "%s", out)
		}

		dumpByCgroupHandler := func(w http.ResponseWriter, r *http.Request) {
			cgroupStr := r.FormValue("cgroup")
			out, err := t.DumpProgByCgroup(cgroupStr)
			if err != nil {
				fmt.Fprintf(w, "%v\n", err)
				return
			}
			fmt.Fprintf(w, "%s", out)
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

		dumpPodHandler := func(w http.ResponseWriter, r *http.Request) {
			namespaceStr := r.FormValue("namespace")
			podnameStr := r.FormValue("podname")
			idxStr := r.FormValue("idx")
			if idxStr == "" {
				fmt.Fprintf(w, "parameter idx missing\n")
				return
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				fmt.Fprintf(w, "%v\n", err)
				return
			}

			out, err := t.DumpPod(namespaceStr, podnameStr, idx)
			if err != nil {
				fmt.Fprintf(w, "%v\n", err)
				return
			}
			fmt.Fprintf(w, "%s", out)
		}

		closeHandler := func(w http.ResponseWriter, r *http.Request) {
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
			err = t.CloseProg(uint32(id))
			if err != nil {
				fmt.Fprintf(w, "%v\n", err)
				return
			}
			fmt.Fprintf(w, "closed\n")
		}

		closeByNameHandler := func(w http.ResponseWriter, r *http.Request) {
			nameStr := r.FormValue("name")
			err = t.CloseProgByName(nameStr)
			if err != nil {
				fmt.Fprintf(w, "%v\n", err)
				return
			}
			fmt.Fprintf(w, "closed\n")
		}

		http.HandleFunc("/list", listHandler)
		http.HandleFunc("/add", addHandler)
		http.HandleFunc("/dump", dumpHandler)
		http.HandleFunc("/dump-pod", dumpPodHandler)
		http.HandleFunc("/dump-by-name", dumpByNameHandler)
		http.HandleFunc("/dump-by-cgroup", dumpByCgroupHandler)
		http.HandleFunc("/close", closeHandler)
		http.HandleFunc("/close-by-name", closeByNameHandler)
		server := http.Server{}

		unixListener, err := net.Listen("unix", "/run/traceloop.socket")
		if err != nil {
			panic(err)
		}
		server.Serve(unixListener)
	}

	var ids []uint32
	for _, cgroupPath := range paths {
		id, err := t.AddProg(cgroupPath, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Added cgroup %q as id %v\n", cgroupPath, id)
		ids = append(ids, id)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	ticker := time.Tick(time.Millisecond * 250)

LOOP:
	for {
		select {
		case <-ticker:
		case <-sig:
			fmt.Printf("Interrupted!\n")
			break LOOP
		}

		for _, id := range ids {
			_ = t.DumpProgWithQueue(id)
			out, err := t.DumpProg(id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			// Clear screen to remove old contents before printing the full log again
			fmt.Printf("\033[2J%s", out)
		}
	}

	t.Stop()
}
