package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// EnvPrefix préfixe toutes les variables d'environnement.
const EnvPrefix = "WP_"

// Field est une clé de configuration : une valeur simple, une liste ou une
// table. Chaque Field a un chemin YAML, une variable d'environnement et un
// flag, déduits de la structure : une clé ne peut pas exister sans sa
// variable (facteur III).
type Field struct {
	Path   string // "collect.cluster"
	Env    string // "WP_COLLECT_CLUSTER"
	Flag   string // "collect.cluster"
	Secret bool
	value  reflect.Value
}

var durationType = reflect.TypeFor[time.Duration]()

// EnvConfigFile désigne le fichier YAML facultatif.
const EnvConfigFile = "WP_CONFIG"

// Fields énumère les clés de cfg, pointeur vers une structure, dans l'ordre
// de déclaration.
func Fields(cfg any) []Field {
	var out []Field
	walk(reflect.ValueOf(cfg).Elem(), nil, false, &out)
	return out
}

// LoadInto applique à cfg (pointeur, déjà rempli de ses défauts) le fichier
// WP_CONFIG puis les variables WP_* ; elle renvoie les variables inconnues.
func LoadInto(cfg any, environ []string) ([]string, error) {
	if path := lookup(environ, EnvConfigFile); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("lecture de la configuration : %w", err)
		}
		if err := ApplyYAML(cfg, data); err != nil {
			return nil, fmt.Errorf("%s : %w", path, err)
		}
	}
	return ApplyEnv(cfg, environ)
}

func lookup(environ []string, key string) string {
	for _, kv := range slices.Backward(environ) {
		if len(kv) > len(key) && kv[:len(key)] == key && kv[len(key)] == '=' {
			return kv[len(key)+1:]
		}
	}
	return ""
}

func walk(v reflect.Value, path []string, secret bool, out *[]Field) {
	t := v.Type()
	for i := range t.NumField() {
		sf := t.Field(i)
		name, _, _ := strings.Cut(sf.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}
		p := append(append([]string{}, path...), name)
		fv := v.Field(i)
		isSecret := secret || sf.Tag.Get("secret") == "true"
		if fv.Kind() == reflect.Struct && fv.Type() != durationType {
			walk(fv, p, isSecret, out)
			continue
		}
		f := Field{Path: strings.Join(p, "."), Flag: strings.Join(p, "."), Secret: isSecret, value: fv}
		if env := sf.Tag.Get("env"); env != "" {
			f.Env = env
		} else {
			f.Env = envName(p)
		}
		*out = append(*out, f)
	}
}

// envName convertit un chemin en nom de variable : collect.syncTimeout donne
// WP_COLLECT_SYNC_TIMEOUT, agent.serverURL donne WP_AGENT_SERVER_URL.
func envName(path []string) string {
	var b strings.Builder
	b.WriteString(EnvPrefix)
	for i, seg := range path {
		if i > 0 {
			b.WriteByte('_')
		}
		r := []rune(seg)
		for j, c := range r {
			if j > 0 && unicode.IsUpper(c) {
				prev := r[j-1]
				nextLower := j+1 < len(r) && unicode.IsLower(r[j+1])
				if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
					b.WriteByte('_')
				}
			}
			b.WriteRune(unicode.ToUpper(c))
		}
	}
	return b.String()
}

// Set affecte une valeur écrite sous forme de texte : durée ("30s"),
// booléen, nombre, liste de chaînes ("a,b" ou JSON) ou JSON pour les listes
// et tables structurées. Une liste ou une table est remplacée, pas fusionnée.
func (f Field) Set(s string) error {
	v := f.value
	switch {
	case v.Type() == durationType:
		d, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		v.SetInt(int64(d))
	case v.Kind() == reflect.String:
		v.SetString(s)
	case v.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return err
		}
		v.SetBool(b)
	case v.CanInt():
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(n)
	case v.CanFloat():
		n, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return err
		}
		v.SetFloat(n)
	case v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.String && !strings.HasPrefix(strings.TrimSpace(s), "["):
		parts := []string{}
		for p := range strings.SplitSeq(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
		v.Set(reflect.ValueOf(parts).Convert(v.Type()))
	default:
		n := reflect.New(v.Type())
		dec := json.NewDecoder(strings.NewReader(s))
		dec.DisallowUnknownFields()
		if err := dec.Decode(n.Interface()); err != nil {
			return fmt.Errorf("JSON attendu : %w", err)
		}
		v.Set(n.Elem())
	}
	return nil
}

// String renvoie la valeur sous forme de texte, au format accepté par Set.
func (f Field) String() string {
	v := f.value
	switch {
	case v.Type() == durationType:
		return time.Duration(v.Int()).String()
	case v.Kind() == reflect.String:
		return v.String()
	case v.Kind() == reflect.Bool, v.CanInt(), v.CanFloat():
		return fmt.Sprint(v.Interface())
	}
	b, _ := json.Marshal(v.Interface())
	return string(b)
}

// IsZero indique si la clé n'a pas de valeur ; une liste ou une table vide
// n'en a pas.
func (f Field) IsZero() bool {
	switch f.value.Kind() {
	case reflect.Slice, reflect.Map:
		return f.value.Len() == 0
	}
	return f.value.IsZero()
}

func (f Field) yamlValue() any {
	if f.value.Type() == durationType {
		return time.Duration(f.value.Int()).String()
	}
	return f.value.Interface()
}

// ApplyYAML applique à cfg (pointeur vers une structure) un fichier
// YAML. Une clé inconnue est une erreur. Chaque clé
// présente remplace la valeur courante, comme une variable d'environnement :
// une table ou une liste n'est pas fusionnée avec la valeur par défaut.
func ApplyYAML(cfg any, data []byte) error {
	check := reflect.New(reflect.TypeOf(cfg).Elem()).Interface()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(check); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	if len(root.Content) == 0 {
		return nil
	}
	for _, f := range Fields(cfg) {
		n := lookupNode(root.Content[0], strings.Split(f.Path, "."))
		if n == nil {
			continue
		}
		fresh := reflect.New(f.value.Type())
		if err := n.Decode(fresh.Interface()); err != nil {
			return fmt.Errorf("%s : %w", f.Path, err)
		}
		f.value.Set(fresh.Elem())
	}
	return nil
}

func lookupNode(n *yaml.Node, path []string) *yaml.Node {
	for _, key := range path {
		if n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				next = n.Content[i+1]
			}
		}
		if next == nil {
			return nil
		}
		n = next
	}
	return n
}

// ApplyEnv applique à cfg (pointeur vers une structure) les variables
// WP_*. Pour une clé secrète, WP_X_FILE désigne un
// fichier dont le contenu fait office de valeur (Secret Kubernetes monté).
// Elle renvoie les variables WP_* qui ne correspondent à aucune clé.
func ApplyEnv(cfg any, environ []string) (unknown []string, err error) {
	env := map[string]string{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, EnvPrefix) {
			env[k] = v
		}
	}
	known := map[string]bool{EnvConfigFile: true}
	var errs []error
	for _, f := range Fields(cfg) {
		known[f.Env] = true
		// Une variable vide vaut absence : Helm rend souvent « VAR: "" ».
		val, ok := env[f.Env]
		ok = ok && val != ""
		if f.Secret {
			known[f.Env+"_FILE"] = true
			if path := env[f.Env+"_FILE"]; path != "" {
				if ok {
					errs = append(errs, fmt.Errorf("%s et %s_FILE sont tous deux définis", f.Env, f.Env))
					continue
				}
				b, rerr := os.ReadFile(path)
				if rerr != nil {
					errs = append(errs, fmt.Errorf("%s_FILE : %w", f.Env, rerr))
					continue
				}
				val, ok = strings.TrimRight(string(b), "\r\n"), true
			}
		}
		if !ok {
			continue
		}
		if err := f.Set(val); err != nil {
			errs = append(errs, fmt.Errorf("%s : %w", f.Env, err))
		}
	}
	for k := range env {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	return unknown, errors.Join(errs...)
}

// RegisterFlags déclare un flag par clé de cfg. Il s'applique à cfg au
// moment de l'analyse des arguments, donc après le fichier et
// l'environnement ; cfg ne doit plus être copié ensuite. defaults (même
// type que cfg) donne les valeurs affichées par -h.
func RegisterFlags(fs *flag.FlagSet, cfg, defaults any) {
	defs := map[string]string{}
	for _, f := range Fields(defaults) {
		if !f.Secret {
			defs[f.Path] = f.String()
		}
	}
	for _, f := range Fields(cfg) {
		usage := "variable " + f.Env
		if f.Secret {
			usage += ", ou " + f.Env + "_FILE (fichier) ; secret"
		}
		fs.Var(flagValue{f}, f.Flag, usage)
		// La valeur affichée par -h est le défaut, pas la valeur venue de
		// l'environnement.
		fs.Lookup(f.Flag).DefValue = defs[f.Path]
	}
}

// Alias déclare un flag court qui règle la même clé qu'un flag existant.
func Alias(fs *flag.FlagSet, alias, target string) {
	f := fs.Lookup(target)
	if f == nil {
		panic("flag inconnu : " + target)
	}
	fs.Var(f.Value, alias, "raccourci de -"+target)
	fs.Lookup(alias).DefValue = f.DefValue
}

type flagValue struct{ f Field }

func (v flagValue) String() string {
	if !v.f.value.IsValid() {
		return ""
	}
	if v.f.Secret {
		return ""
	}
	return v.f.String()
}

func (v flagValue) Set(s string) error { return v.f.Set(s) }

// IsBoolFlag permet d'écrire -agent.allowInsecure sans valeur.
func (v flagValue) IsBoolFlag() bool { return v.f.value.IsValid() && v.f.value.Kind() == reflect.Bool }

// Redacted rend cfg en YAML, secrets masqués.
func Redacted(cfg any) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode}
	for _, f := range Fields(cfg) {
		node := root
		parts := strings.Split(f.Path, ".")
		for _, p := range parts[:len(parts)-1] {
			node = child(node, p)
		}
		var val yaml.Node
		v := f.yamlValue()
		if f.Secret && !f.IsZero() {
			v = "********"
		} else if str, ok := v.(string); ok {
			v = RedactURL(str)
		}
		if err := val.Encode(v); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: parts[len(parts)-1]}, &val)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

func child(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	c := &yaml.Node{Kind: yaml.MappingNode}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, c)
	return c
}
