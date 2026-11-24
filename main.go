// Agent Wardpod : collecte un cluster Kubernetes (workloads, exposition,
// privilèges, vulnérabilités et SBOM de ses images) et l'envoie à la
// console Wardpod.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/ThomasSamson/wardpod-agent/agent"
	"github.com/ThomasSamson/wardpod-agent/config"
	"github.com/ThomasSamson/wardpod-agent/version"
	"k8s.io/klog/v2"
)

// command est une sous-commande. setup déclare ses flags propres et renvoie
// son action, exécutée après l'analyse des arguments.
type command struct {
	summary string
	setup   func(fs *flag.FlagSet, cfg *config.Config) *action
}

type action struct {
	run func(ctx context.Context, env *runEnv) error
	// dataOnStdout indique que la sortie standard porte le résultat de la
	// commande (YAML, JSON) : les logs passent alors sur la sortie d'erreur.
	dataOnStdout func() bool
	// args décrit les arguments positionnels acceptés ; vide, il n'en accepte
	// aucun.
	args string
}

// runEnv regroupe ce que reçoit une sous-commande.
type runEnv struct {
	cfg    *config.Config
	args   []string
	stdout io.Writer
	stderr io.Writer
	stdin  io.Reader
}

var commands = map[string]command{}

func register(name string, c command) { commands[name] = c }

func init() {
	register("agent", agentCommand)
	register("config", configCommand)
	register("version", versionCommand)
}

func always() bool { return true }

func main() {
	os.Exit(run(os.Args[1:], os.Environ(), os.Stdin, os.Stdout, os.Stderr))
}

// errUsage signale une erreur d'utilisation (code de sortie 2).
var errUsage = errors.New("utilisation incorrecte")

func run(args, environ []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Tant que la commande et la configuration ne sont pas connues, les logs
	// vont sur la sortie d'erreur : la sortie standard peut porter un résultat.
	setupLogging(stderr, config.Default().Log)

	if len(args) == 0 || args[0] == "-h" || args[0] == "-help" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "sous-commande inconnue : %s\n\n", args[0])
		usage(stderr)
		return 2
	}

	cfg, unknown, err := config.Load(environ)
	if err != nil {
		slog.Error("configuration illisible", "err", err)
		return 1
	}
	fs := flag.NewFlagSet("wardpod "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg.RegisterFlags(fs)
	act := cmd.setup(fs, &cfg)
	fs.Usage = func() { commandUsage(stderr, args[0], cmd, act, fs) }
	positional, err := parseInterspersed(fs, args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.Usage()
			return 0
		}
		fmt.Fprintf(stderr, "%s\n`wardpod %s -h` liste les options.\n", flagError(err), args[0])
		return 2
	}
	if act.args == "" && len(positional) > 0 {
		// Sans ce contrôle, « -agent.allowInsecure false » activerait
		// l'option : flag lit « false » comme un argument et l'ignorerait.
		fmt.Fprintf(stderr, "argument inattendu : %q (une option booléenne s'écrit -option=false)\n", positional[0])
		return 2
	}

	logOut := stdout
	if act.dataOnStdout != nil && act.dataOnStdout() {
		logOut = stderr
	}
	setupLogging(logOut, cfg.Log)
	for _, k := range unknown {
		slog.Warn("variable d'environnement inconnue, ignorée", "variable", k)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err = act.run(ctx, &runEnv{cfg: &cfg, args: positional, stdout: stdout, stderr: stderr, stdin: stdin})
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		fmt.Fprintln(stderr, err)
		return 2
	default:
		slog.Error("arrêt sur erreur", "command", args[0], "err", err)
		return 1
	}
}

// parseInterspersed accepte les options avant comme après les arguments
// positionnels (« agent -dump -cluster test ») ; « -- » termine les
// options, sauf s'il est la valeur d'une option (« -name -- »).
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var after []string
	for i, a := range args {
		if a == "--" && (i == 0 || !needsValue(fs, args[i-1])) {
			args, after = args[:i], args[i+1:]
			break
		}
	}
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return append(positional, after...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// needsValue indique si arg est une option qui attend une valeur dans
// l'argument suivant.
func needsValue(fs *flag.FlagSet, arg string) bool {
	if len(arg) < 2 || arg[0] != '-' || strings.Contains(arg, "=") {
		return false
	}
	f := fs.Lookup(strings.TrimLeft(arg, "-"))
	if f == nil {
		return false
	}
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return !ok || !b.IsBoolFlag()
}

// flagError traduit les erreurs du paquet flag.
func flagError(err error) string {
	msg := err.Error()
	for _, t := range []struct{ en, fr string }{
		{"flag provided but not defined: ", "option inconnue : "},
		{"flag needs an argument: ", "option sans valeur : "},
		{"bad flag syntax: ", "syntaxe d'option incorrecte : "},
	} {
		if rest, ok := strings.CutPrefix(msg, t.en); ok {
			return t.fr + rest
		}
	}
	if rest, ok := strings.CutPrefix(msg, "invalid value "); ok {
		// invalid value "x" for flag -y: cause
		if val, tail, ok := strings.Cut(rest, " for flag "); ok {
			name, cause, _ := strings.Cut(tail, ": ")
			return fmt.Sprintf("valeur %s invalide pour l'option %s : %s", val, name, cause)
		}
	}
	if rest, ok := strings.CutPrefix(msg, "invalid boolean value "); ok {
		if val, tail, ok := strings.Cut(rest, " for "); ok {
			name, _, _ := strings.Cut(tail, ": ")
			return fmt.Sprintf("valeur booléenne %s invalide pour l'option %s", val, name)
		}
	}
	return msg
}

// setupLogging écrit les logs sur w, en JSON par défaut (facteur XI). Les
// logs de client-go suivent le même chemin.
func setupLogging(w io.Writer, cfg config.Log) {
	level, err := config.ParseLevel(cfg.Level)
	if err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if cfg.Format == "text" {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	slog.SetDefault(slog.New(h).With("version", version.Version))
	// klog n'est pas prévu pour changer de logger pendant que client-go
	// tourne : il est branché une fois sur un handler qui suit le logger
	// par défaut courant.
	klogOnce.Do(func() {
		klog.SetSlogLogger(slog.New(defaultHandler{}).With("component", "client-go"))
	})
}

var klogOnce sync.Once

// defaultHandler délègue au handler de slog.Default() au moment de l'appel.
// Les attributs et groupes sont rejoués dans l'ordre où ils ont été posés.
type defaultHandler struct {
	ops []func(slog.Handler) slog.Handler
}

func (d defaultHandler) target() slog.Handler {
	h := slog.Default().Handler()
	for _, op := range d.ops {
		h = op(h)
	}
	return h
}

func (d defaultHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return slog.Default().Handler().Enabled(ctx, l)
}

func (d defaultHandler) Handle(ctx context.Context, r slog.Record) error {
	return d.target().Handle(ctx, r)
}

func (d defaultHandler) with(op func(slog.Handler) slog.Handler) defaultHandler {
	return defaultHandler{ops: append(append([]func(slog.Handler) slog.Handler{}, d.ops...), op)}
}

func (d defaultHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return d.with(func(h slog.Handler) slog.Handler { return h.WithAttrs(attrs) })
}

func (d defaultHandler) WithGroup(name string) slog.Handler {
	return d.with(func(h slog.Handler) slog.Handler { return h.WithGroup(name) })
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "Wardpod %s\n\nUtilisation : wardpod <sous-commande> [options]\n\nSous-commandes :\n", version.String())
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-14s %s\n", n, commands[n].summary)
	}
	fmt.Fprintf(w, "\nChaque option de configuration est aussi une variable WP_* ; voir config.example.yaml.\n`wardpod <sous-commande> -h` liste les options.\n")
}

func commandUsage(w io.Writer, name string, cmd command, act *action, fs *flag.FlagSet) {
	fmt.Fprintf(w, "wardpod %s : %s\n\nUtilisation : wardpod %s [options] %s\n\nOptions (valeur par défaut entre crochets) :\n", name, cmd.summary, name, act.args)
	fs.VisitAll(func(f *flag.Flag) {
		def := ""
		if f.DefValue != "" {
			def = " [" + f.DefValue + "]"
		}
		fmt.Fprintf(w, "  -%s%s\n      %s\n", f.Name, def, f.Usage)
	})
}

var versionCommand = command{
	summary: "affiche la version",
	setup: func(*flag.FlagSet, *config.Config) *action {
		return &action{dataOnStdout: always, run: func(_ context.Context, env *runEnv) error {
			_, err := fmt.Fprintln(env.stdout, version.String())
			return err
		}}
	},
}

var configCommand = command{
	summary: "affiche la configuration effective, secrets masqués",
	setup: func(fs *flag.FlagSet, _ *config.Config) *action {
		check := fs.String("check", "", "valide aussi la configuration pour un usage : agent ou mcp")
		return &action{dataOnStdout: always, run: func(_ context.Context, env *runEnv) error {
			validate := env.cfg.ValidateCommon
			switch *check {
			case "":
			case "agent":
				validate = func() error {
					return errors.Join(env.cfg.ValidateCommon(), agent.ValidateSources(env.cfg.Collect, env.cfg.Scanner), agent.ValidateHTTP(env.cfg.Agent))
				}
			case "mcp":
				validate = func() error { return errors.Join(env.cfg.ValidateCommon(), validateMCP(env.cfg.MCP)) }
			default:
				return fmt.Errorf("%w : -check vaut agent ou mcp (%q)", errUsage, *check)
			}
			out, err := env.cfg.Redacted()
			if err != nil {
				return err
			}
			if _, err := env.stdout.Write(out); err != nil {
				return err
			}
			if err := validate(); err != nil {
				return fmt.Errorf("configuration invalide : %w", err)
			}
			return nil
		}}
	},
}
