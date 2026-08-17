package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const bootstrapLockName = ".bootstrap.lock"

// BootstrapDir creates a mesh CA and named node certs under dir if they
// are missing. Existing files are left alone. Node name "foo" uses
// foo.pem / foo.crt and SAN hopscotch:foo.
func BootstrapDir(dir string, names []string) error {
	if dir == "" {
		return fmt.Errorf("bootstrap dir required")
	}
	names, err := NormalizeNames(names)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("at least one node name required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return withMkdirLock(filepath.Join(dir, bootstrapLockName), func() error {
		return bootstrapDirLocked(dir, names)
	})
}

// bootstrapDirLocked creates missing CA and node certs under dir while locked.
func bootstrapDirLocked(dir string, names []string) error {
	caKey := filepath.Join(dir, "ca.key")
	caCert := filepath.Join(dir, "ca.crt")
	keyOK := fileExists(caKey)
	certOK := fileExists(caCert)
	switch {
	case !keyOK && !certOK:
		if err := InitCAFiles(caKey, caCert); err != nil {
			return err
		}
	case keyOK && certOK:
	default:
		return fmt.Errorf("need both %s and %s", caKey, caCert)
	}
	for _, name := range names {
		out := filepath.Join(dir, name+".crt")
		if fileExists(out) {
			continue
		}
		id := filepath.Join(dir, name+".pem")
		if err := SignNodeFiles(caKey, caCert, id, out, name); err != nil {
			return err
		}
	}
	return nil
}

// withMkdirLock runs fn while holding an exclusive mkdir-based lock at lockDir.
func withMkdirLock(lockDir string, fn func() error) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := os.Mkdir(lockDir, 0o700)
		if err == nil {
			defer os.Remove(lockDir)
			return fn()
		}
		if !os.IsExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			_ = os.Remove(lockDir)
			deadline = time.Now().Add(30 * time.Second)
			continue
		}
		time.Sleep(50 * time.Millisecond)
	}
}
