package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Masterminds/log-go"
	"github.com/crooks/ssh-rcopy-id/config"
	"github.com/crooks/sshcmds"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	cfg   *config.Config
	flags *config.Flags
)

const (
	auth_keys_extension string = ".auth"
)

type Targets struct {
	hostNames []string
	userNames []string
}

// ParseLoglevel returns the loglevel integer associated with a common loglevel
// string representation.
func ParseLoglevel(loglevelStr string) (level int, err error) {
	switch strings.ToLower(loglevelStr) {
	case "trace":
		level = log.TraceLevel
	case "debug":
		level = log.DebugLevel
	case "info":
		level = log.InfoLevel
	case "warn":
		level = log.WarnLevel
	case "warning":
		level = log.WarnLevel
	case "error":
		level = log.ErrorLevel
	case "panic":
		level = log.PanicLevel
	case "fatal":
		level = log.FatalLevel
	default:
		err = fmt.Errorf("unknown loglevel: %s", loglevelStr)
	}
	return
}

// newTargets returns a new instance of Targets
func newTargets() *Targets {
	return &Targets{}
}

// splitHostNames splits a comma separated string of hostnames into a slice
func (t *Targets) splitHostNames(h string) {
	// Deal with comma separated hostNames and userNames flags
	t.hostNames = strings.Split(flags.Hosts, ",")
	if len(t.hostNames) == 1 && t.hostNames[0] == "" {
		log.Fatal("No destination hostnames specified")
	}
}

// readAuthFiles gathers all the filenames in a given directory.  The desired filename format is <username>.auth where
// username is the name of the user on the remote host.  The file content will be written to the authorized_keys file
// of that user.
func (t *Targets) readAuthFiles(dir string) {
	file, err := os.Open(dir)
	if err != nil {
		log.Fatal("Unable to open auth files directory: %v", err)
	}
	defer file.Close()
	fileList, err := file.ReadDir(-1)
	if err != nil {
		log.Fatalf("Unable to read auth files: %v", err)
	}
	for _, f := range fileList {
		if filepath.Ext(f.Name()) == auth_keys_extension {
			userName := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name()))
			log.Debugf("Adding %s to users list", userName)
			t.userNames = append(t.userNames, userName)
		}
	}
}

// isDir returns true if a given path exists and is a directory
func isDir(path string) (bool, error) {
	stat, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // Path doesn't exist
		} else {
			return false, err // Some unexpected error occured
		}
	} else if stat.IsDir() {
		return true, nil // Path exists and is a directory
	}
	return false, nil // Path exists but isn't a directory
}

// Scp pushes a file from the source to the client.
func Scp(client *ssh.Client, srcPath, dstPath string) error {
	sftp, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sftp.Close()
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	dstFile, err := sftp.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	if _, err := dstFile.ReadFrom(srcFile); err != nil {
		return err
	}
	return nil
}

// setKeys takes a map keyed by username and containing associated public key files.  It returns an ssh Config object.
func setKeys() *sshcmds.Config {
	// Create an instance of the sshcmds library
	sshcfg := sshcmds.NewConfig()
	// Iterate through configured keyfiles and associated user names
	for k, v := range cfg.Authentication.SSHKeys {
		log.Debugf("Adding SSH key %s for user %s", k, v)
		err := sshcfg.AddKey(v, path.Join(cfg.Authentication.SSHKeyDir, k))
		if err != nil {
			log.Fatalf("Unable to add SSH key: %v", err)
		}
	}
	return sshcfg
}

// iterUsers takes a hostName and an ssh.Client object and performs a series of SSH commands against a range of userNames.
func (t *Targets) iterUsers(hostName string, client *ssh.Client) {
	for _, userName := range t.userNames {
		sshID := fmt.Sprintf("%s@%s", userName, hostName)
		err := userAuth(hostName, userName, client)
		if err != nil {
			log.Warnf("%s: Failed with: %v", sshID, err)
			continue
		}
		log.Infof("%s: User successfully processed", sshID)
	}
}

func userAuth(hostName, userName string, client *ssh.Client) error {
	sshID := fmt.Sprintf("%s@%s", userName, hostName)
	userDir := path.Join(cfg.Dest.BaseHomedir, userName)
	userSSHDir := path.Join(userDir, cfg.Dest.KeyDir)
	userAuthKeysFile := path.Join(userSSHDir, cfg.Dest.AuthKeysFile)
	srcKeyFile := path.Join(cfg.Source.KeyDir, userName+auth_keys_extension)
	// Create an sftp instance
	sftpc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("SFTP connection failure: %v", err)
	}
	defer sftpc.Close()
	// Test if the user has a homedir.  If not, ignore it and move on.
	stat, err := sftpc.Stat(userDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Debugf("%s: Homedir %s does not exist.", sshID, userDir)
			return nil
		} else {
			return fmt.Errorf("SFTP Stat failure: %v", err)
		}
	}
	if !stat.IsDir() {
		log.Debugf("%s: %s is not a directory. Ignoring.", sshID, userDir)
		return nil
	}
	// userDirStat contains the UID and GID of the homedir.  This is useful later for chown on the .ssh dir.
	userDirStat := stat.Sys().(*sftp.FileStat)

	// Test if an authorized_keys file already exists for this user.  If it does, don't overwrite it.
	stat, err = sftpc.Stat(userAuthKeysFile)
	if err == nil {
		if stat.IsDir() {
			return fmt.Errorf("%s is a directory", userAuthKeysFile)
		} else {
			log.Debugf("%s: %s already exists", sshID, userAuthKeysFile)
			return nil
		}
	} else if errors.Is(err, os.ErrNotExist) {
		// This is the only result that doesn't abort this user iteration.
		log.Debugf("%s: %s doesn't exist.  Attempting to create it.", sshID, userAuthKeysFile)
	} else {
		return fmt.Errorf("SFTP Stat failure: %v", err)
	}

	stat, err = sftpc.Stat(userSSHDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Debugf("%s: SSH dir %s does not exist.  Creating it.", sshID, userSSHDir)
			err = sftpc.Mkdir(userSSHDir)
			if err != nil {
				return fmt.Errorf("unable to create %s: %v", userSSHDir, err)
			}
		} else {
			return fmt.Errorf("SFTP Stat failure: %v", err)
		}
		// This check can only be done if err = nil, otherwise it will segfault.
	} else if !stat.IsDir() {
		return fmt.Errorf("%s is not a directory", userSSHDir)
	}

	// Set the owner of the SSH dir to match the parent (E.g. /home/username)
	log.Debugf("%s: Doing chown %d:%d %s", sshID, int(userDirStat.UID), int(userDirStat.GID), userSSHDir)
	err = sftpc.Chown(userSSHDir, int(userDirStat.UID), int(userDirStat.GID))
	if err != nil {
		log.Warnf("%s: Failed to chown %s", sshID, userSSHDir)
	}
	// Chmod the ssh dir to 0700
	log.Debugf("%s: Doing chmod 0700 %s", sshID, userSSHDir)
	err = sftpc.Chmod(userSSHDir, 0700)
	if err != nil {
		log.Warnf("%s: Failed to chmod 0700 %s", sshID, userSSHDir)
	}
	// Actually do the SCP of the authorized_keys file
	log.Debugf("Performing SCP from %s to %s", srcKeyFile, userAuthKeysFile)
	err = Scp(client, srcKeyFile, userAuthKeysFile)
	if err != nil {
		return fmt.Errorf("scp failed: %v", err)
	}
	// Set the owner of the authorized_keys file to match the parent (E.g. /home/username)
	log.Debugf("%s: Doing chown %d:%d %s", sshID, int(userDirStat.UID), int(userDirStat.GID), userAuthKeysFile)
	err = sftpc.Chown(userAuthKeysFile, int(userDirStat.UID), int(userDirStat.GID))
	if err != nil {
		log.Warnf("%s: Failed to chown %s", sshID, userAuthKeysFile)
	}
	// Set permissions on the authorized_keys file
	log.Debugf("%s: Doing chmod 0600 %s", sshID, userAuthKeysFile)
	err = sftpc.Chmod(userAuthKeysFile, 0600)
	if err != nil {
		log.Warnf("%s: Failed to chmod 0600 %s", sshID, userAuthKeysFile)
	}
	return nil
}

// iterTargets iterates over a slice of hosts and establishes an SSH client session with them.
func (t *Targets) iterTargets(ssh *sshcmds.Config) {
	for _, hostName := range t.hostNames {
		log.Infof("Performing actions on host: %s", hostName)
		client, err := ssh.Auth(hostName)
		if err != nil {
			log.Fatalf("%s: Authentication failure: %v", hostName, err)
		}
		t.iterUsers(hostName, client)
		client.Close()
	}
}

// configParse populates the cfg global variable and performs some config validation.
func configParse(filename string) {
	var err error
	cfg, err = config.ParseConfig(filename)
	if err != nil {
		log.Fatalf("Unable to parse config: %v", err)
	}
	if flags.Loglevel != "" {
		cfg.LogLevel = flags.Loglevel
	}
	// If the keydir flag has been specified, override the config setting
	if flags.KeyDir != "" {
		cfg.Source.KeyDir = config.ExpandTilde(flags.KeyDir)
	}
	// The destdir flag overrides the config file specification.
	if flags.DestDir != "" {
		cfg.Dest.KeyDir = config.ExpandTilde(flags.DestDir)
	}
	isdir, err := isDir(cfg.Source.KeyDir)
	if err != nil {
		log.Fatalf("%s: Error parsing Key Directory: %v", cfg.Source.KeyDir, err)
	}
	if !isdir {
		log.Fatalf("%[1]s is not a directory.  Use --keydir=<dir> or source.ssh_keys_dir in %[2]s or mkdir %[1]s", cfg.Source.KeyDir, filename)
	}
	if len(cfg.Authentication.SSHKeys) < 1 {
		log.Fatalf("No SSH keys specified for authenticating with clients")
	}
}

func main() {
	var err error
	// Do initial set up of flags, config and logging
	flags = config.ParseFlags()
	configParse(flags.Config)
	loglevel, err := ParseLoglevel(cfg.LogLevel)
	if err != nil {
		log.Fatalf("Unable to parse log level: %v", err)
	}
	log.Current = log.StdLogger{Level: loglevel}
	// cfg.Source.SSHKeys defines the keys to use for authentication to the destination hosts (probably root keys)
	ssh := setKeys()
	t := newTargets()
	t.splitHostNames(flags.Hosts)
	t.readAuthFiles(cfg.Source.KeyDir)
	t.iterTargets(ssh)
}
