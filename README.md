# Remote Search (hostsearch)

A memory-efficient Go CLI tool for searching files across multiple remote hosts via SSH/SFTP in parallel.

## Features

- **Multi-host parallel search**: Search multiple remote hosts simultaneously
- **Memory efficient**: O(1) memory usage - results streamed directly to file
- **Real-time progress**: Live multi-line display showing progress for each host
- **Multi-pattern matching**: Search for multiple file types in a single pass
- **YAML configuration**: Named host shortcuts for easy management

## Installation

```bash
go build -o hostsearch cmd/search/main.go
```

## Quick Start

1. Create `config.yaml`:
```yaml
hosts:
  nas1: ssh://user:password@192.168.1.10:22
  nas2: ssh://user:password@192.168.1.20:22

folders:
  - /mnt
  - /data

exclude_dirs:
  - /mnt/tmp
  - /data/cache
```

2. Run a search:
```bash
# Search specific hosts
./hostsearch -c config.yaml -h nas1,nas2 -out results.txt "*.mp3,*.mp4"

# Search all configured hosts
./hostsearch -c config.yaml --all -out media.txt "*.mkv,*.avi"
```

## Usage

```bash
hostsearch -c <config> -h <hosts>|--all -out <file> "<patterns>"

Required:
  -c <path>       Path to config.yaml
  -h <hosts>      Comma-separated host names (e.g., nas1,nas2)
  --all           Search all hosts in config
  -out <file>     Output file for results
  <patterns>      Comma-separated file patterns (e.g., "*.mp3,*.mp4")

Optional:
  -concurrency <n>        Number of parallel workers (default: host count)
  -roots <paths>          Search roots, semicolon separated
  -exclude-dirs <paths>   Directories to exclude, semicolon separated
```

## Configuration

### Host Format
```yaml
hosts:
  name: ssh://username:password@host:port
```

### Optional Settings
```yaml
folders:              # Directories to search (default: /home, /mnt, /media, /srv)
  - /data
  - /backup

exclude_dirs:         # Directories to skip (default: system dirs)
  - /data/tmp
  - /backup/old

max_depth: 10         # Maximum directory depth (optional)
```

## Output

Results written to file in format:
```
hostname: /path/to/matched/file
```

Progress display shows real-time updates:
```
nas1:  2293 scanned | 15 found | /mnt/media/music
nas2:  1847 scanned | 8 found  | /data/videos
```

## Requirements

- Go 1.x or higher
- SSH access to remote hosts
- Password-based authentication

## License

[Your license here]
