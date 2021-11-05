package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/traceloop/pkg/straceback"
)

var (
	serveHTTP  bool
	withPidNS  bool
	dumpOnExit bool
	paths      []string

	logflags string
)

// This variable is set during build.
var version = "undefined"

func increaseRlimit() error {
	limit := &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, limit)
}

func main() {
	flag.StringVar(&logflags, "log", "info", "log level [trace,debug,info,warn,error,fatal,color,nocolor,json]")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "%s [OPTIONS] <k8s>|<guess>|<serve>|<cgroups [--dump-on-exit] CGROUPS...>\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "  guess:                   Look for newly created Docker containers.\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  k8s:                     Look for newly created Docker containers and start daemon with HTTP API on /run/traceloop.socket.\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  serve:                   Start daemon with HTTP API on /run/traceloop.socket.\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  cgroups CGROUPS...:      One or more arguments to specify the CGroup path(s) to attach to.\n")
		fmt.Fprintf(flag.CommandLine.Output(), "                           The ring buffer contents are continuously dumped.\n")
		fmt.Fprintf(flag.CommandLine.Output(), "                           The optional flag --dump-on-exit disables interactive usage\n")
		fmt.Fprintf(flag.CommandLine.Output(), "                           so that the dump is only done when the traceloop process is terminated.\n")
		fmt.Fprintf(flag.CommandLine.Output(), "\n")

		flag.PrintDefaults()

	}
	flag.Parse()

	for _, v := range strings.Split(logflags, ",") {
		if v == "json" {
			log.SetFormatter(&log.JSONFormatter{})
		} else if v == "color" {
			log.SetFormatter(&log.TextFormatter{ForceColors: true})
		} else if v == "nocolor" {
			log.SetFormatter(&log.TextFormatter{DisableColors: true})
		} else if lvl, err := log.ParseLevel(v); err == nil {
			log.SetLevel(lvl)
		} else {
			fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", err.Error())
			flag.Usage()
			os.Exit(1)
		}
	}

	fmt.Printf("traceloop version %v\n", version)
	guessCmd := flag.NewFlagSet("guess", flag.ExitOnError)
	guessCmd.Usage = flag.Usage
	k8sCmd := flag.NewFlagSet("k8s", flag.ExitOnError)
	k8sCmd.Usage = flag.Usage
	serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
	serveCmd.Usage = flag.Usage
	cgroupsCmd := flag.NewFlagSet("cgroups", flag.ExitOnError)
	dumpOnExitEnable := cgroupsCmd.Bool("dump-on-exit", false, "dump-on-exit")
	cgroupsCmd.Usage = flag.Usage
	if len(flag.Args()) == 0 || flag.Arg(0) == "-h" || flag.Arg(0) == "--help" || flag.Arg(0) == "help" {
		flag.Usage()
		os.Exit(0)
	}
	switch flag.Arg(0) {
	case "guess":
		_ = guessCmd.Parse(flag.Args()[1:])
		withPidNS = true
		args := guessCmd.Args()
		if len(args) > 0 {
			fmt.Fprintf(os.Stderr, "Unexpected additional arguments: %q.\n", args)
			flag.Usage()
			os.Exit(1)
		}
	case "k8s":
		_ = k8sCmd.Parse(flag.Args()[1:])
		withPidNS = true
		serveHTTP = true
		args := k8sCmd.Args()
		if len(args) > 0 {
			fmt.Fprintf(os.Stderr, "Unexpected additional arguments: %q.\n", args)
			flag.Usage()
			os.Exit(1)
		}
	case "serve":
		_ = serveCmd.Parse(flag.Args()[1:])
		serveHTTP = true
		args := serveCmd.Args()
		if len(args) > 0 {
			fmt.Fprintf(os.Stderr, "Unexpected additional arguments: %q.\n", args)
			flag.Usage()
			os.Exit(1)
		}
	case "cgroups":
		_ = cgroupsCmd.Parse(flag.Args()[1:])
		dumpOnExit = *dumpOnExitEnable
		paths = cgroupsCmd.Args()
		if len(paths) == 0 {
			fmt.Fprintf(os.Stderr, "No cgroup paths specified.\n")
			flag.Usage()
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown argument %q.\n", flag.Arg(0))
		flag.Usage()
		os.Exit(1)
	}

	if err := increaseRlimit(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to increase memlock limit: %v\n", err)
		os.Exit(1)
	}

	t, err := straceback.NewTracer(withPidNS, withPidNS, withPidNS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if withPidNS && !serveHTTP {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		fmt.Printf("Interrupted!\n")
		t.DumpAll()
		os.Exit(0)
	}

	if serveHTTP {
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

		dumpByTraceidHandler := func(w http.ResponseWriter, r *http.Request) {
			traceidStr := r.FormValue("traceid")
			out, err := t.DumpProgByTraceid(traceidStr)
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
		http.HandleFunc("/dump-by-traceid", dumpByTraceidHandler)
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
	signal.Notify(sig, os.Interrupt)

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
