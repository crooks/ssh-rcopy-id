package config

import (
	"flag"
	"os"
	"os/user"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

type Flags struct {
	Config   string
	Hosts    string
	KeyDir   string
	Loglevel string
}

type Config struct {
	LogLevel       string `yaml:"loglevel"`
	Authentication struct {
		SSHKeyDir string            `yaml:"ssh_dir"`
		SSHKeys   map[string]string `yaml:"ssh_private_keys"`
	} `yaml:"authentication"`
	Source struct {
		KeyDir string `yaml:"ssh_keys_dir"`
	} `yaml:"source"`
	Dest struct {
		BaseHomedir  string `yaml:"base_homedir"`
		KeyDir       string `yaml:"ssh_dir"`
		AuthKeysFile string `yaml:"authorized_keys"`
	} `yaml:"destination"`
}

func ParseConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	y := yaml.NewDecoder(file)
	config := new(Config)
	// Read the config file
	if err := y.Decode(&config); err != nil {
		return nil, err
	}
	// Make info the default loglevel
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}
	// By default on Unix/Linux systems, SSH key pairs will be in ~/.ssh
	if config.Authentication.SSHKeyDir == "" {
		config.Authentication.SSHKeyDir = ExpandTilde("~/.ssh")
	} else {
		config.Authentication.SSHKeyDir = ExpandTilde(config.Authentication.SSHKeyDir)
	}
	// Try to guess the source directory for public keys
	if config.Source.KeyDir == "" {
		config.Source.KeyDir = path.Join(pwd(), "keys")
	} else {
		config.Source.KeyDir = ExpandTilde(config.Source.KeyDir)
	}
	if config.Dest.BaseHomedir == "" {
		config.Dest.BaseHomedir = "/home"
	}
	// It would be unusual to put the ssh authorized_keys file anywhere besides /home/foo/.ssh
	if config.Dest.KeyDir == "" {
		config.Dest.KeyDir = ".ssh"
	}
	if config.Dest.AuthKeysFile == "" {
		config.Dest.AuthKeysFile = "authorized_keys"
	}
	return config, nil
}

func ParseFlags() *Flags {
	f := new(Flags)
	flag.StringVar(&f.Config, "config", "ssh-rcopy-id.yml", "Path to the config file")
	flag.StringVar(&f.Hosts, "hosts", "", "Comma seperated list of hostnames")
	flag.StringVar(&f.KeyDir, "keydir", "", "Location of the public keys directory on the source host")
	flag.StringVar(&f.Loglevel, "loglevel", "", "Override the default loglevel (info)")
	flag.Parse()
	return f
}

// expandTilde expands filenames and paths that use the tilde convention to imply relative to homedir.
func ExpandTilde(inPath string) (outPath string) {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	if inPath == "~" {
		outPath = u.HomeDir
	} else if strings.HasPrefix(inPath, "~/") {
		outPath = path.Join(u.HomeDir, inPath[2:])
	} else {
		outPath = inPath
	}
	return
}

func pwd() string {
	path, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return path
}
