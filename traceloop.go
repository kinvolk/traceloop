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
	serveHttp  bool
	dumpOnExit bool
	paths      []string
)

func main() {
	if len(os.Args) == 1 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		fmt.Printf("Usage:\n%s <serve>|<CGROUPS...>|<signal-dump CGROUPS...>\n", os.Args[0])
		fmt.Printf("  serve:                   Start daemon with HTTP API on /run/traceloop.socket.\n")
		fmt.Printf("  CGROUPS...:              One or more arguments to specify the CGroup path(s) to attach to.\n")
		fmt.Printf("                           The ring buffer contents are continuously dumped.\n")
		fmt.Printf("  dump-on-exit CGROUPS...: As above but only dump when the traceloop process is killed.\n")
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "serve" {
		serveHttp = true
	} else {
		if os.Args[1] == "dump-on-exit" {
			dumpOnExit = true
			paths = os.Args[2:]
		} else {
			paths = os.Args[1:]
		}
		if len(paths) == 0 {
			fmt.Fprintf(os.Stderr, "No cgroup paths specified.\n")
			os.Exit(1)
		}
	}

	t, err := straceback.NewTracer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
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

	terminate := false

	for !terminate {
		select {
			case <-ticker:
				if dumpOnExit {
					continue
				}
			case <-sig:
				terminate = true
		}

		for n, id := range ids {
			cgroupPath, err := t.GetCgroupPath(id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			_ = t.DumpProgWithQueue(id)
			out, err := t.DumpProg(id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			clearScreen := ""
			if n == 0 && !dumpOnExit {
				// Clear screen to remove old contents before printing the full log again
				clearScreen = "\033[2J"
			}
			fmt.Printf("%s\nDump for %s:\n%sEnd of dump for %s (Press Ctrl-S to pause, Ctrl-Q to continue, Ctrl-C to quit)\n",
				clearScreen, cgroupPath, out, cgroupPath)
		}

		if terminate {
			fmt.Printf("Interrupted!\n")
			break
		}
	}

	t.Stop()
}
