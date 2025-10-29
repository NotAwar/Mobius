package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/notawar/mobius/server/api/server/mdm/nanodep/client"
	"github.com/notawar/mobius/server/api/server/mdm/nanodep/storage"
)

const defaultFileMode = 0644

// sanitizeName validates and sanitizes the DEP name to prevent path traversal attacks.
func sanitizeName(name string) (string, error) {
	if name == "" {
		return "", errors.New("name cannot be empty")
	}
	// Remove any path separators or traversal attempts
	clean := filepath.Base(name)
	// Ensure the cleaned name doesn't contain dangerous characters
	if strings.Contains(clean, "..") || strings.ContainsAny(clean, "/\\") {
		return "", fmt.Errorf("invalid name contains path traversal characters: %q", name)
	}
	if clean == "." || clean == ".." {
		return "", fmt.Errorf("invalid name: %q", name)
	}
	return clean, nil
}

// FileStorage implements filesystem-based storage for DEP services.
type FileStorage struct {
	path string
}

var _ storage.AllDEPStorage = (*FileStorage)(nil)

// New creates a new FileStorage backend.
func New(path string) (*FileStorage, error) {
	err := os.Mkdir(path, 0755)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			f, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			if !f.IsDir() {
				return nil, errors.New("path is not a directory")
			}
		} else {
			return nil, err
		}
	}
	return &FileStorage{path: path}, nil
}

func (s *FileStorage) tokensFilename(name string) (string, error) {
	clean, err := sanitizeName(name)
	if err != nil {
		return "", err
	}
	return path.Join(s.path, clean+".tokens.json"), nil
}

func (s *FileStorage) configFilename(name string) (string, error) {
	clean, err := sanitizeName(name)
	if err != nil {
		return "", err
	}
	return path.Join(s.path, clean+".config.json"), nil
}

func (s *FileStorage) profileFilename(name string) (string, error) {
	clean, err := sanitizeName(name)
	if err != nil {
		return "", err
	}
	return path.Join(s.path, clean+".profile.txt"), nil
}

func (s *FileStorage) cursorFilename(name string) (string, error) {
	clean, err := sanitizeName(name)
	if err != nil {
		return "", err
	}
	return path.Join(s.path, clean+".cursor.txt"), nil
}

func (s *FileStorage) tokenpkiFilename(name, kind string) (string, error) {
	clean, err := sanitizeName(name)
	if err != nil {
		return "", err
	}
	// Sanitize kind as well
	cleanKind := filepath.Base(kind)
	if cleanKind != kind || strings.ContainsAny(cleanKind, "/\\") {
		return "", fmt.Errorf("invalid kind: %q", kind)
	}
	return path.Join(s.path, clean+".tokenpki."+cleanKind+".txt"), nil
}

// RetrieveAuthTokens reads the JSON DEP OAuth tokens from disk for name DEP name.
func (s *FileStorage) RetrieveAuthTokens(_ context.Context, name string) (*client.OAuth1Tokens, error) {
	filename, err := s.tokensFilename(name)
	if err != nil {
		return nil, err
	}
	tokens := new(client.OAuth1Tokens)
	err = decodeJSONfile(filename, tokens)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, storage.ErrNotFound
		}
		return nil, err
	}
	return tokens, nil
}

// StoreAuthTokens saves the DEP OAuth tokens to disk as JSON for name DEP name.
func (s *FileStorage) StoreAuthTokens(_ context.Context, name string, tokens *client.OAuth1Tokens) error {
	filename, err := s.tokensFilename(name)
	if err != nil {
		return err
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(tokens)
}

func decodeJSONfile(filename string, v interface{}) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(v)
}

// RetrieveConfig reads the JSON DEP config from disk for name DEP name.
//
// Returns an empty config if the config does not exist (to support a fallback default config).
func (s *FileStorage) RetrieveConfig(_ context.Context, name string) (*client.Config, error) {
	filename, err := s.configFilename(name)
	if err != nil {
		return nil, err
	}
	config := new(client.Config)
	err = decodeJSONfile(filename, config)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		// an 'empty' config is valid
		return &client.Config{}, nil
	}
	return config, err
}

// StoreConfig saves the DEP config to disk as JSON for name DEP name.
func (s *FileStorage) StoreConfig(_ context.Context, name string, config *client.Config) error {
	filename, err := s.configFilename(name)
	if err != nil {
		return err
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(config)
}

// RetrieveAssignerProfile reads the assigner profile UUID and its configured
// timestamp from disk for name DEP name.
//
// Returns an empty profile if it does not exist.
func (s *FileStorage) RetrieveAssignerProfile(_ context.Context, name string) (string, time.Time, error) {
	filename, err := s.profileFilename(name)
	if err != nil {
		return "", time.Time{}, err
	}
	profileBytes, err := os.ReadFile(filename)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		// an 'empty' profile is valid
		return "", time.Time{}, nil
	}
	modTime := time.Time{}
	if err == nil {
		var stat fs.FileInfo
		stat, err = os.Stat(filename)
		if err == nil {
			modTime = stat.ModTime()
		}
	}
	return strings.TrimSpace(string(profileBytes)), modTime, err
}

// StoreAssignerProfile saves the assigner profile UUID to disk for name DEP name.
func (s *FileStorage) StoreAssignerProfile(_ context.Context, name string, profileUUID string) error {
	filename, err := s.profileFilename(name)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, []byte(profileUUID+"\n"), defaultFileMode)
}

// RetrieveCursor reads the reads the DEP fetch and sync cursor from disk
// for name DEP name. We return an empty cursor if the cursor does not exist
// on disk.
func (s *FileStorage) RetrieveCursor(_ context.Context, name string) (string, time.Time, error) {
	filename, err := s.cursorFilename(name)
	if err != nil {
		return "", time.Time{}, err
	}
	cursorBytes, err := os.ReadFile(filename)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		// an 'empty' cursor is valid
		return "", time.Time{}, nil
	}
	modTime := time.Time{}
	if err == nil {
		var stat fs.FileInfo
		stat, err = os.Stat(filename)
		if err == nil {
			modTime = stat.ModTime()
		}
	}
	return strings.TrimSpace(string(cursorBytes)), modTime, err
}

// StoreCursor saves the DEP fetch and sync cursor to disk for name DEP name.
func (s *FileStorage) StoreCursor(_ context.Context, name, cursor string) error {
	filename, err := s.cursorFilename(name)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, []byte(cursor+"\n"), defaultFileMode)
}

// StoreTokenPKI stores the PEM bytes in pemCert and pemKey to disk for name DEP name.
func (s *FileStorage) StoreTokenPKI(_ context.Context, name string, pemCert []byte, pemKey []byte) error {
	certFilename, err := s.tokenpkiFilename(name, "cert")
	if err != nil {
		return err
	}
	if err := os.WriteFile(certFilename, pemCert, 0664); err != nil { //nolint:gosec
		return err
	}
	keyFilename, err := s.tokenpkiFilename(name, "key")
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyFilename, pemKey, 0664); err != nil { //nolint:gosec
		return err
	}
	return nil
}

// RetrieveTokenPKI reads and returns the PEM bytes for the DEP token exchange
// certificate and private key from disk using name DEP name.
func (s *FileStorage) RetrieveTokenPKI(_ context.Context, name string) ([]byte, []byte, error) {
	certFilename, err := s.tokenpkiFilename(name, "cert")
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := os.ReadFile(certFilename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, storage.ErrNotFound
		}
		return nil, nil, err
	}
	keyFilename, err := s.tokenpkiFilename(name, "key")
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := os.ReadFile(keyFilename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, storage.ErrNotFound
		}
		return nil, nil, err
	}
	return certBytes, keyBytes, err
}
