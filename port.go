package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

type LogConfig struct {
	Enabled bool   `toml:"enabled" json:"enabled"`
	Path    string `toml:"path" json:"path"`
}

type Config struct {
	Scan struct {
		IP        string `toml:"ip"`
		TimeoutMS int    `toml:"timeout_ms"`
		StartPort int    `toml:"start_port"`
		EndPort   int    `toml:"end_port"`
		Workers   int    `toml:"workers"`
	} `toml:"scan"`
	Paths struct {
		PortData  string `toml:"port_data" json:"port_data"`
		LuaData   string `toml:"lua_data" json:"lua_data"`
		Script    string `toml:"script" json:"script"`
		Bootstrap string `toml:"bootstrap" json:"bootstrap"`
		Policy    string `toml:"policy" json:"policy"`
		Proc      string `toml:"proc" json:"proc"`
	} `toml:"paths" json:"paths"`
	Commands struct {
		Lua  string `toml:"lua"`
		Lsof string `toml:"lsof"`
	} `toml:"commands"`
	Node struct {
		URL string `toml:"url" json:"url"`
	} `toml:"node" json:"node"`
	Logging struct {
		Enabled bool      `toml:"enabled" json:"enabled"`
		Scan    LogConfig `toml:"scan"`
		Config  LogConfig `toml:"config"`
		Node    LogConfig `toml:"node"`
		Danger  LogConfig `toml:"danger"`
		Kill    LogConfig `toml:"kill"`
		Jester  struct {
			Enabled        bool   `toml:"enabled" json:"enabled"`
			Path           string `toml:"path" json:"path"`
			MaxFileSize    int    `toml:"max_file_size" json:"max_file_size"`
			MaxBackupIndex int    `toml:"max_backup_index" json:"max_backup_index"`
		} `toml:"jester" json:"jester"`
	} `toml:"logging" json:"logging"`
}

func defaultConfig() Config {
	var cfg Config
	cfg.Logging.Enabled = true
	cfg.Logging.Scan = LogConfig{Enabled: true}
	cfg.Logging.Config = LogConfig{Enabled: true}
	cfg.Logging.Node = LogConfig{Enabled: true}
	cfg.Logging.Danger = LogConfig{Enabled: true}
	cfg.Logging.Kill = LogConfig{Enabled: true}
	cfg.Logging.Jester.Enabled = true
	return cfg
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Scan.StartPort < 1 || cfg.Scan.EndPort > 65535 || cfg.Scan.EndPort < cfg.Scan.StartPort ||
		cfg.Scan.Workers < 1 || cfg.Scan.Workers > cfg.Scan.EndPort-cfg.Scan.StartPort+1 || cfg.Scan.TimeoutMS < 1 {
		return cfg, fmt.Errorf("%s: invalid scan range, workers, or timeout_ms", path)
	}
	for name, value := range map[string]string{
		"scan.ip": cfg.Scan.IP, "paths.port_data": cfg.Paths.PortData,
		"paths.lua_data": cfg.Paths.LuaData, "paths.script": cfg.Paths.Script,
		"paths.bootstrap": cfg.Paths.Bootstrap, "paths.policy": cfg.Paths.Policy,
		"paths.proc": cfg.Paths.Proc, "commands.lua": cfg.Commands.Lua,
		"commands.lsof": cfg.Commands.Lsof, "node.url": cfg.Node.URL,
	} {
		if value == "" {
			return cfg, fmt.Errorf("%s: %s is required", path, name)
		}
	}
	if cfg.Logging.Enabled && cfg.Logging.Jester.Enabled &&
		(cfg.Logging.Jester.Path == "" || cfg.Logging.Jester.MaxFileSize < 1 || cfg.Logging.Jester.MaxBackupIndex < 1) {
		return cfg, fmt.Errorf("%s: jester logging requires a path and positive rotation limits", path)
	}
	return cfg, nil
}

type PortsProcess struct {
	goScanned   string
	nodeScanned string
}

var (
	scanLog   *slog.Logger
	configLog *slog.Logger
	nodeLog   *slog.Logger
	dangerLog *slog.Logger
	killLog   *slog.Logger
)

func initLogger(cfg Config) (func(), error) {
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	discardLog := slog.New(slog.NewJSONHandler(io.Discard, opts))
	if !cfg.Logging.Enabled {
		scanLog, configLog, nodeLog, dangerLog, killLog = discardLog, discardLog, discardLog, discardLog, discardLog
		return func() {}, nil
	}

	var files []*os.File
	cleanup := func() {
		for _, file := range files {
			file.Close()
		}
	}
	for _, entry := range []struct {
		config LogConfig
		logger **slog.Logger
		name   string
	}{
		{cfg.Logging.Scan, &scanLog, "scanner"},
		{cfg.Logging.Config, &configLog, "config"},
		{cfg.Logging.Node, &nodeLog, "node"},
		{cfg.Logging.Danger, &dangerLog, "port"},
		{cfg.Logging.Kill, &killLog, "port"},
	} {
		if !entry.config.Enabled {
			*entry.logger = discardLog
			continue
		}
		if entry.config.Path == "" {
			cleanup()
			return nil, fmt.Errorf("%s log: path is required when enabled", entry.name)
		}
		file, err := os.OpenFile(
			entry.config.Path,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644,
		)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("%s log: %w", entry.name, err)
		}
		files = append(files, file)
		*entry.logger = slog.New(slog.NewJSONHandler(file, opts))
	}

	// cleanup func — call this in main() defer
	return cleanup, nil
}

func activePorts(start int, end int, wg *sync.WaitGroup, p *PortsProcess, mu *sync.RWMutex, cfg Config) {
	var (
		tempGoScanned     = make(map[int]string)
		tempJsonGoScanned []byte
	)
	defer wg.Done()

	for port := start; port <= end; port++ {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(cfg.Scan.IP, strconv.Itoa(port)), time.Duration(cfg.Scan.TimeoutMS)*time.Millisecond)
		if err != nil {
			// connection refused / timeout = expected, not an error worth logging
			continue
		}
		conn.Close()

		cmd, err := exec.Command(
			cfg.Commands.Lsof, "-nP",
			fmt.Sprintf("-iTCP:%d", port),
			"-sTCP:LISTEN", "-t",
		).Output()

		if err != nil {
			// lsof failing on an open port is unusual — log it
			scanLog.Warn("lsof failed for port",
				"port", port,
				"err", err,
			)
			continue
		}

		tempGoScanned[port] = strings.TrimSpace(string(cmd))
	}

	tempJsonGoScanned, err := json.Marshal(tempGoScanned)

	if err != nil {
		scanLog.Error("failed to marshal scanned ports", "range_start", start, "range_end", end, "err", err)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if p.goScanned == "" {
		p.goScanned = string(tempJsonGoScanned)
	} else {
		merged := make(map[int]string)
		if err := json.Unmarshal([]byte(p.goScanned), &merged); err != nil {
			scanLog.Error("failed to unmarshal existing goScanned", "err", err)
			return
		}
		if err := json.Unmarshal(tempJsonGoScanned, &merged); err != nil {
			scanLog.Error("failed to unmarshal new chunk", "err", err)
			return
		}
		result, err := json.Marshal(merged)
		if err != nil {
			scanLog.Error("failed to marshal merged ports", "err", err)
			return
		}
		p.goScanned = string(result)
	}
}

func runConfig(p *PortsProcess, cfg Config) bool {
	data, err := json.Marshal(map[string]string{
		"goScanned":   p.goScanned,
		"nodeScanned": p.nodeScanned,
	})
	if err != nil {
		configLog.Error("failed to marshal config data", "err", err)
		panic(err) // config serialization failing = unrecoverable
	}

	if err := os.WriteFile(cfg.Paths.PortData, data, 0644); err != nil {
		configLog.Error("failed to write port_data.json", "err", err)
		panic(err) // lua script needs this file
	}

	configData, err := json.Marshal(cfg)
	if err != nil {
		configLog.Error("failed to marshal shared config", "err", err)
		panic(err)
	}
	cmd := exec.Command(cfg.Commands.Lua, cfg.Paths.Script)
	// Jester uses the same decoded TOML without needing a second TOML parser.
	cmd.Env = append(os.Environ(), "JESTER_CONFIG="+string(configData))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		configLog.Error("lua script failed", "err", err)
		panic(err)
	}
	return true
}

func readUncontrolledPorts(cfg Config) {
	data, err := os.ReadFile(cfg.Paths.LuaData)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			configLog.Debug("lua_data.json not found, skipping uncontrolled ports")
			return
		}
		configLog.Error("failed to read lua_data.json", "err", err)
		return
	}
	err = os.Remove(cfg.Paths.LuaData)
	if err != nil {
		configLog.Error("failed to remove file", "err", err)
	}

	var parsedUncontrolledPorts map[string]interface{}
	if err := json.Unmarshal(data, &parsedUncontrolledPorts); err != nil {
		configLog.Error("failed to parse lua_data.json", "err", err)
		return
	}

	for port, action := range parsedUncontrolledPorts {
		pidBytes, err := exec.Command(
			cfg.Commands.Lsof, "-nP",
			fmt.Sprintf("-iTCP:%s", port),
			"-sTCP:LISTEN", "-t",
		).Output()
		if err != nil {
			configLog.Warn("lsof failed for uncontrolled port", "port", port, "err", err)
			continue
		}

		pidInt, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
		if err != nil {
			configLog.Warn("invalid PID from lsof", "port", port, "raw", string(pidBytes), "err", err)
			continue
		}

		proc, err := os.FindProcess(pidInt)
		if err != nil {
			configLog.Error("failed to find process", "pid", pidInt, "port", port, "err", err)
			continue
		}

		switch action {
		case "kill":
			if err := proc.Signal(syscall.SIGTERM); err != nil {
				killLog.Error("SIGTERM failed", "pid", pidInt, "port", port, "err", err)
			} else {
				killLog.Info("sent SIGTERM", "pid", pidInt, "port", port)
			}
		case "destroy":
			if err := proc.Kill(); err != nil {
				dangerLog.Error("SIGKILL failed", "pid", pidInt, "port", port, "err", err)
			} else {
				dangerLog.Warn("SIGKILL failed", "pid", pidInt, "port", port, "err", err)
			}
		default:
			dangerLog.Warn("unknown action for port", "port", port, "action", action)
		}
	}
}

func runNode(wg *sync.WaitGroup, p *PortsProcess, cfg Config) {
	defer wg.Done()

	res, err := http.Get(cfg.Node.URL)
	if err != nil {
		nodeLog.Error("failed to reach node API", "err", err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		nodeLog.Warn("node API returned non-200", "status", res.StatusCode)
		return
	}

	nodeRes, err := io.ReadAll(res.Body)
	if err != nil {
		nodeLog.Error("failed to read node API response", "err", err)
		return
	}

	p.nodeScanned = string(nodeRes)
}

func main() {
	configPath := flag.String("config", "harbinger.toml", "path to the shared Harbinger/Jester TOML config")
	flag.Parse()
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}
	cleanup, err := initLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init loggers: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()

	var (
		wg        sync.WaitGroup
		mu        sync.RWMutex
		openPorts = PortsProcess{}
	)

	var (
		startPort  = cfg.Scan.StartPort
		endPort    = cfg.Scan.EndPort
		workers    = cfg.Scan.Workers
		totalPorts = endPort - startPort + 1
		perWorker  = totalPorts / workers
	)

	for w := 0; w < workers; w++ {
		start := startPort + (w * perWorker)
		end := startPort + ((w + 1) * perWorker) - 1
		if w == workers-1 {
			end = endPort
		}
		wg.Add(1)
		go activePorts(start, end, &wg, &openPorts, &mu, cfg)
	}

	wg.Add(1)
	go runNode(&wg, &openPorts, cfg)
	wg.Wait()
	config_status := runConfig(&openPorts, cfg)
	if config_status == false {
		return
	}
	readUncontrolledPorts(cfg)
}
