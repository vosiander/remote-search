// hostsearch.go
// A Go utility that SSHes into multiple hosts in parallel and searches
// for files matching a name or extension, while pruning excluded directories.
//
// Uses YAML configuration with named hosts for easy management.
//
// Example config.yaml:
//
//	hosts:
//	  unraid: ssh://admin:password@10.0.0.50:22
//	  qnapnas: ssh://user:pass@10.0.0.20
//
// Example usage:
//
//	./hostsearch -c config.yaml -h unraid,qnapnas "*.mp3"
//	./hostsearch -c config.yaml --all "*.log"
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// Config represents the YAML configuration file
type Config struct {
	Hosts       map[string]string `yaml:"hosts"`
	Folders     []string          `yaml:"folders,omitempty"`
	ExcludeDirs []string          `yaml:"exclude_dirs,omitempty"`
	MaxDepth    int               `yaml:"max_depth,omitempty"`
}

// SSHConfig holds parsed SSH connection details
type SSHConfig struct {
	name     string
	username string
	password string
	host     string
	port     string
}

// sensible defaults
var (
	defaultRoots    = []string{"/home", "/mnt", "/media", "/srv"}
	defaultExcludes = []string{"/proc", "/sys", "/dev", "/run", "/tmp", "/var/log", "/var/tmp", "/var/cache", "/lost+found"}
)

// normalizeList splits on ';' or ',' and trims whitespace.
func normalizeList(s string) []string {
	if s == "" {
		return nil
	}
	replacer := strings.NewReplacer(";", ",")
	s = replacer.Replace(s)
	parts := strings.Split(s, ",")
	var out []string
	seen := make(map[string]struct{})
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; !ok {
			out = append(out, p)
			seen[p] = struct{}{}
		}
	}
	return out
}

// buildPatterns interprets comma-separated user input into glob patterns
func buildPatterns(input string) []string {
	parts := strings.Split(input, ",")
	var patterns []string

	for _, part := range parts {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}

		var pattern string
		if strings.ContainsAny(s, "*?[]") {
			pattern = s
		} else if !strings.Contains(s, ".") && !strings.Contains(s, "/") && !strings.Contains(s, "\\") {
			pattern = "*." + s
		} else {
			pattern = "*" + s + "*"
		}
		patterns = append(patterns, pattern)
	}

	if len(patterns) == 0 {
		return []string{"*"}
	}
	return patterns
}

// matchAnyPattern checks if filename matches any of the patterns (case-insensitive)
func matchAnyPattern(patterns []string, name string) bool {
	lowerName := strings.ToLower(name)
	for _, pattern := range patterns {
		match, err := filepath.Match(strings.ToLower(pattern), lowerName)
		if err == nil && match {
			return true
		}
	}
	return false
}

// isExcluded checks if a path should be excluded
func isExcluded(fullPath string, excludes []string) bool {
	for _, exclude := range excludes {
		if strings.HasPrefix(fullPath, exclude) {
			return true
		}
	}
	return false
}

// createSFTPClient creates an SFTP client from SSH config
func createSFTPClient(cfg *SSHConfig, timeout time.Duration) (*ssh.Client, *sftp.Client, error) {
	config := &ssh.ClientConfig{
		User: cfg.username,
		Auth: []ssh.AuthMethod{
			ssh.Password(cfg.password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	addr := cfg.host + ":" + cfg.port
	sshClient, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect: %w", err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		return nil, nil, fmt.Errorf("failed to create SFTP client: %w", err)
	}

	return sshClient, sftpClient, nil
}

// walkRemoteDir walks a remote directory via SFTP and finds matching files
// Returns only the count of matches found (files are written directly to disk)
func walkRemoteDir(client *sftp.Client, root string, patterns []string, excludes []string, maxDepth int, progressCh chan<- progressUpdate, hostName string, outFileHandle *os.File, outFileMutex *sync.Mutex) (int, error) {
	var totalFiles int
	var matchCount int

	// Check if root exists
	info, err := client.Stat(root)
	if err != nil {
		return 0, fmt.Errorf("directory does not exist: %w", err)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("path is not a directory")
	}

	// Walk the directory
	err = walkDir(client, root, root, patterns, excludes, maxDepth, 0, &totalFiles, &matchCount, progressCh, hostName, outFileHandle, outFileMutex)
	return matchCount, err
}

// walkDir is a recursive helper function for walking directories
// No longer stores matches in memory - writes directly to file
func walkDir(client *sftp.Client, basePath, currentPath string, patterns []string, excludes []string, maxDepth int, currentDepth int, totalFiles *int, matchCount *int, progressCh chan<- progressUpdate, hostName string, outFileHandle *os.File, outFileMutex *sync.Mutex) error {
	// Check maxDepth
	if maxDepth > 0 && currentDepth >= maxDepth {
		return nil
	}

	// Check if current path is excluded
	if isExcluded(currentPath, excludes) {
		log.WithField("path", currentPath).Debug("Skipping excluded directory")
		return nil
	}

	entries, err := client.ReadDir(currentPath)
	if err != nil {
		// Log the error but continue with other directories
		log.WithField("path", currentPath).Debugf("Error reading directory: %v", err)
		return nil
	}

	// Send progress update for this directory
	progressCh <- progressUpdate{
		hostName:     hostName,
		message:      currentPath,
		filesScanned: *totalFiles,
		filesMatched: *matchCount,
	}

	for _, entry := range entries {
		fullPath := path.Join(currentPath, entry.Name())

		if entry.IsDir() {
			// Recursively walk subdirectories
			if err := walkDir(client, basePath, fullPath, patterns, excludes, maxDepth, currentDepth+1, totalFiles, matchCount, progressCh, hostName, outFileHandle, outFileMutex); err != nil {
				return err
			}
		} else {
			*totalFiles++

			// Check if file matches ANY of the patterns
			if matchAnyPattern(patterns, entry.Name()) {
				*matchCount++

				// Write to file immediately (no in-memory storage)
				outFileMutex.Lock()
				fmt.Fprintf(outFileHandle, "%s: %s\n", hostName, fullPath)
				// Sync every 10 matches to ensure data is written to disk
				if *matchCount%10 == 0 {
					outFileHandle.Sync()
				}
				outFileMutex.Unlock()
			}

			// Send periodic updates (every 100 files)
			if *totalFiles%100 == 0 {
				progressCh <- progressUpdate{
					hostName:     hostName,
					message:      currentPath,
					filesScanned: *totalFiles,
					filesMatched: *matchCount,
				}
			}
		}
	}

	return nil
}

// loadConfig reads and parses the YAML configuration file
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if len(config.Hosts) == 0 {
		return nil, fmt.Errorf("no hosts defined in config file")
	}

	return &config, nil
}

// parseSSHURL parses an SSH URL and returns SSHConfig
func parseSSHURL(name, rawURL string) (*SSHConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %w", err)
	}

	if u.Scheme != "ssh" {
		return nil, fmt.Errorf("URL must use ssh:// scheme")
	}

	if u.Host == "" {
		return nil, fmt.Errorf("missing host in URL")
	}

	username := u.User.Username()
	if username == "" {
		return nil, fmt.Errorf("missing username in URL")
	}

	password, hasPassword := u.User.Password()
	if !hasPassword {
		return nil, fmt.Errorf("missing password in URL")
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "22"
	}

	return &SSHConfig{
		name:     name,
		username: username,
		password: password,
		host:     host,
		port:     port,
	}, nil
}

// result holds the search results for a host (no file paths stored in memory)
type result struct {
	name      string
	host      string
	stderr    string
	err       error
	fileCount int
}

// progressUpdate represents a real-time progress update
type progressUpdate struct {
	hostName     string
	message      string
	filesScanned int
	filesMatched int
}

// hostProgress tracks progress display for each host
type hostProgress struct {
	name    string
	message string
	files   int
	found   int
	lineNum int // Line number in the display (0-based)
}

// progressDisplay manages the multi-line progress display
type progressDisplay struct {
	hosts    []string
	progress map[string]*hostProgress
	mu       sync.Mutex
}

// newProgressDisplay creates a new progress display
func newProgressDisplay(hostNames []string) *progressDisplay {
	pd := &progressDisplay{
		hosts:    hostNames,
		progress: make(map[string]*hostProgress),
	}

	// Initialize progress for each host
	for i, name := range hostNames {
		pd.progress[name] = &hostProgress{
			name:    name,
			message: "Initializing...",
			files:   0,
			found:   0,
			lineNum: i,
		}
	}

	// Print initial lines for each host
	for range hostNames {
		fmt.Println()
	}

	return pd
}

// update updates the display for a specific host
func (pd *progressDisplay) update(hostName string, files, found int, message string) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if hp, exists := pd.progress[hostName]; exists {
		if files > 0 {
			hp.files = files
		}
		if found > 0 {
			hp.found = found
		}
		hp.message = message

		// Move cursor up to this host's line and update it
		linesToMoveUp := len(pd.hosts) - hp.lineNum
		fmt.Printf("\033[%dA", linesToMoveUp) // Move cursor up
		fmt.Printf("\r\033[K")                // Clear line
		fmt.Printf("%-15s %d scanned | %d found | %s", hp.name+":", hp.files, hp.found, hp.message)
		fmt.Printf("\033[%dB", linesToMoveUp) // Move cursor back down
		fmt.Print("\r")                       // Return to start of line
	}
}

// finish marks the display as complete
func (pd *progressDisplay) finish() {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	// Move cursor to the end
	fmt.Println()
}

func main() {
	// log.SetLevel(log.DebugLevel) // Set to Debug level

	configPath := flag.String("c", "", "Path to config.yaml file (required)")
	hostsFlag := flag.String("h", "", "Comma-separated host names to search (e.g., 'unraid,qnapnas')")
	allHosts := flag.Bool("all", false, "Search all hosts in config")

	rootsFlag := flag.String("roots", strings.Join(defaultRoots, ";"), "Search roots (semicolon or comma separated)")
	excludeFlag := flag.String("exclude-dirs", strings.Join(defaultExcludes, ";"), "Directories to exclude (semicolon or comma separated)")
	outFile := flag.String("out", "", "Output file to write results (format: servername: /path/to/file)")

	concurrency := flag.Int("concurrency", 0, "Parallelism (0 = number of hosts, fallback to CPUs)")

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Error("usage: hostsearch -c config.yaml [-h hosts|--all] -out <file> <patterns>")
		log.Error("  patterns: comma-separated list of file patterns (e.g., '*.mp3,*.mp4,*.mkv')")
		flag.PrintDefaults()
		os.Exit(2)
	}

	if *configPath == "" {
		log.Error("config file is required (use -c flag)")
		os.Exit(2)
	}

	if *outFile == "" {
		log.Error("output file is required (use -out flag)")
		os.Exit(2)
	}

	if *hostsFlag == "" && !*allHosts {
		log.Error("must specify either -h with host names or --all")
		os.Exit(2)
	}

	if *hostsFlag != "" && *allHosts {
		log.Error("cannot use both -h and --all flags together")
		os.Exit(2)
	}

	// Load config
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Errorf("failed to load config: %v", err)
		os.Exit(1)
	}

	// Determine which hosts to search
	var hostNames []string
	if *allHosts {
		for name := range config.Hosts {
			hostNames = append(hostNames, name)
		}
		sort.Strings(hostNames)
	} else {
		hostNames = normalizeList(*hostsFlag)
		for _, name := range hostNames {
			if _, exists := config.Hosts[name]; !exists {
				log.Errorf("host '%s' not found in config", name)
				os.Exit(1)
			}
		}
	}

	// Parse SSH configs
	var sshConfigs []*SSHConfig
	for _, name := range hostNames {
		urlStr := config.Hosts[name]
		cfg, err := parseSSHURL(name, urlStr)
		if err != nil {
			log.Errorf("failed to parse URL for host '%s': %v", name, err)
			os.Exit(1)
		}
		sshConfigs = append(sshConfigs, cfg)
	}

	patterns := buildPatterns(args[0])
	log.Infof("Searching for patterns: %v", patterns)

	// Use folders from config if defined, otherwise use CLI flag or defaults
	var roots []string
	if len(config.Folders) > 0 {
		roots = config.Folders
	} else if *rootsFlag != strings.Join(defaultRoots, ";") {
		// User specified custom roots via CLI
		roots = normalizeList(*rootsFlag)
	} else {
		// Use defaults
		roots = defaultRoots
	}

	// Use exclude_dirs from config if defined, otherwise use CLI flag or defaults
	var excludes []string
	if len(config.ExcludeDirs) > 0 {
		excludes = config.ExcludeDirs
	} else if *excludeFlag != strings.Join(defaultExcludes, ";") {
		// User specified custom excludes via CLI
		excludes = normalizeList(*excludeFlag)
	} else {
		// Use defaults
		excludes = defaultExcludes
	}

	// Decide concurrency
	par := *concurrency
	if par <= 0 {
		par = len(sshConfigs)
		if par <= 0 {
			par = runtime.NumCPU()
		}
	}
	if par > len(sshConfigs) {
		par = len(sshConfigs)
	}

	hostCh := make(chan *SSHConfig)
	resCh := make(chan result)
	progressCh := make(chan progressUpdate, 100)
	var wg sync.WaitGroup

	maxDepth := config.MaxDepth

	// Open output file (mandatory)
	outFileHandle, err := os.Create(*outFile)
	if err != nil {
		log.Errorf("Failed to create output file: %v", err)
		os.Exit(1)
	}
	defer outFileHandle.Close()
	var outFileMutex sync.Mutex
	log.Infof("Writing results to %s", *outFile)

	// Create custom progress display
	display := newProgressDisplay(hostNames)

	worker := func() {
		defer wg.Done()
		for cfg := range hostCh {
			var totalMatchCount int
			var errors []string
			hasError := false

			// Send progress update - connecting
			progressCh <- progressUpdate{
				hostName:     cfg.name,
				message:      "Connecting...",
				filesScanned: 0,
				filesMatched: 0,
			}

			// Create SFTP client
			sshClient, sftpClient, err := createSFTPClient(cfg, 10*time.Second)
			if err != nil {
				progressCh <- progressUpdate{
					hostName:     cfg.name,
					message:      "Failed to connect",
					filesScanned: 0,
					filesMatched: 0,
				}
				log.WithField("host", cfg.name).Errorf("Failed to connect: %v", err)
				resCh <- result{
					name:      cfg.name,
					host:      cfg.host,
					stderr:    err.Error(),
					err:       err,
					fileCount: 0,
				}
				continue
			}
			defer sshClient.Close()
			defer sftpClient.Close()

			progressCh <- progressUpdate{
				hostName:     cfg.name,
				message:      "Connected, starting search...",
				filesScanned: 0,
				filesMatched: 0,
			}

			// Search each root directory separately
			for _, root := range roots {
				progressCh <- progressUpdate{
					hostName:     cfg.name,
					message:      fmt.Sprintf("Starting search in %s", root),
					filesScanned: 0,
					filesMatched: 0,
				}

				matchCount, err := walkRemoteDir(sftpClient, root, patterns, excludes, maxDepth, progressCh, cfg.name, outFileHandle, &outFileMutex)
				if err != nil {
					progressCh <- progressUpdate{
						hostName:     cfg.name,
						message:      fmt.Sprintf("Skipping %s (%v)", root, err),
						filesScanned: 0,
						filesMatched: totalMatchCount,
					}
					errors = append(errors, fmt.Sprintf("%s: %v", root, err))
					hasError = true
					continue
				}

				// Final sync for this root directory
				if matchCount > 0 {
					outFileMutex.Lock()
					outFileHandle.Sync()
					outFileMutex.Unlock()
				}

				progressCh <- progressUpdate{
					hostName:     cfg.name,
					message:      fmt.Sprintf("Completed %s", root),
					filesScanned: 0,
					filesMatched: totalMatchCount + matchCount,
				}

				log.WithFields(log.Fields{
					"host":  cfg.name,
					"dir":   root,
					"found": matchCount,
				}).Debugf("Found %d matching files", matchCount)

				totalMatchCount += matchCount
			}

			// Send completion update
			progressCh <- progressUpdate{
				hostName:     cfg.name,
				message:      "Complete!",
				filesScanned: 0,
				filesMatched: totalMatchCount,
			}

			var finalErr error
			if hasError {
				finalErr = fmt.Errorf("errors occurred during search")
			}

			resCh <- result{
				name:      cfg.name,
				host:      cfg.host,
				stderr:    strings.Join(errors, "; "),
				err:       finalErr,
				fileCount: totalMatchCount,
			}
		}
	}

	wg.Add(par)
	for i := 0; i < par; i++ {
		go worker()
	}
	go func() {
		for _, cfg := range sshConfigs {
			hostCh <- cfg
		}
		close(hostCh)
	}()

	// Progress monitor goroutine
	go func() {
		for update := range progressCh {
			display.update(update.hostName, update.filesScanned, update.filesMatched, update.message)
		}
	}()

	// Collector
	var results []result
	for i := 0; i < len(sshConfigs); i++ {
		r := <-resCh
		results = append(results, r)

		// Mark host as complete
		display.update(r.name, 0, r.fileCount, "Complete!")
	}
	wg.Wait()
	close(progressCh)

	// Finish the display
	display.finish()

	// Print errors if any
	for _, r := range results {
		if r.err != nil {
			log.Infof("\n===== %s (%s) =====", r.name, r.host)
			msg := strings.TrimSpace(r.stderr)
			if msg == "" {
				msg = r.err.Error()
			}
			log.WithField("host", r.name).Errorf("%s", msg)
		}
	}

	// Summary table (sorted by name)
	sort.Slice(results, func(i, j int) bool { return results[i].name < results[j].name })
	log.Info("\n===== SUMMARY =====")
	total := 0
	for _, r := range results {
		status := "ok"
		if r.err != nil {
			status = "error"
		}
		log.Infof("%s: %d file(s) [%s]", r.name, r.fileCount, status)
		total += r.fileCount
	}
	log.Infof("TOTAL: %d file(s)", total)

	log.Infof("\nAll results written to %s", *outFile)
}
