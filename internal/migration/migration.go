package migration

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/connection"
	"github.com/gocql/gocql"
)

//go:embed cql/*.cql
var migrationFiles embed.FS

type Config struct {
	Enabled bool
	Table   string
	Timeout time.Duration
}

type Migration struct {
	Version  int
	Name     string
	Filename string
	Checksum string
	Content  string
}

func Run(ctx context.Context, session connection.SessionInterface, cfg Config) error {
	if !cfg.Enabled {
		return nil
	}
	if session == nil || session.Closed() {
		return errors.New("cannot run Cassandra migrations without an open session")
	}
	if strings.TrimSpace(cfg.Table) == "" {
		cfg.Table = "schema_migrations"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}

	runCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	if err := validateIdentifier(cfg.Table); err != nil {
		return fmt.Errorf("invalid migration table: %w", err)
	}
	if err := ensureMigrationTable(runCtx, session, cfg.Table); err != nil {
		return err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	for _, migration := range migrations {
		if err := applyMigration(runCtx, session, cfg.Table, migration); err != nil {
			return err
		}
	}
	return nil
}

func ensureMigrationTable(ctx context.Context, session connection.SessionInterface, table string) error {
	statement := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	version int PRIMARY KEY,
	name text,
	checksum text,
	applied_at timestamp,
	dirty boolean
)`, table)

	if err := session.Query(statement).WithContext(ctx).Exec(); err != nil {
		return fmt.Errorf("create migration table %s: %w", table, err)
	}
	return nil
}

func applyMigration(
	ctx context.Context,
	session connection.SessionInterface,
	table string,
	migration Migration,
) error {
	var (
		checksum string
		dirty    bool
	)

	query := fmt.Sprintf(
		"SELECT checksum, dirty FROM %s WHERE version = ?",
		table,
	)
	err := session.Query(query, migration.Version).
		WithContext(ctx).
		Consistency(gocql.Quorum).
		Scan(&checksum, &dirty)

	switch {
	case err == nil:
		if dirty {
			return fmt.Errorf(
				"migration V%03d (%s) is marked dirty; repair it before restarting",
				migration.Version,
				migration.Name,
			)
		}
		if checksum != migration.Checksum {
			return fmt.Errorf(
				"migration V%03d (%s) checksum changed: database=%s embedded=%s",
				migration.Version,
				migration.Name,
				checksum,
				migration.Checksum,
			)
		}
		return nil

	case !errors.Is(err, gocql.ErrNotFound):
		return fmt.Errorf(
			"read migration V%03d state: %w",
			migration.Version,
			err,
		)
	}

	markDirty := fmt.Sprintf(
		"INSERT INTO %s (version, name, checksum, applied_at, dirty) VALUES (?, ?, ?, ?, ?)",
		table,
	)
	if err := session.Query(
		markDirty,
		migration.Version,
		migration.Name,
		migration.Checksum,
		time.Now().UTC(),
		true,
	).WithContext(ctx).Consistency(gocql.Quorum).Exec(); err != nil {
		return fmt.Errorf("mark migration V%03d dirty: %w", migration.Version, err)
	}

	statements, err := splitCQLStatements(migration.Content)
	if err != nil {
		return fmt.Errorf("parse migration %s: %w", migration.Filename, err)
	}

	for index, statement := range statements {
		if err := session.Query(statement).
			WithContext(ctx).
			Consistency(gocql.Quorum).
			Exec(); err != nil {
			return fmt.Errorf(
				"apply migration V%03d statement %d: %w",
				migration.Version,
				index+1,
				err,
			)
		}
	}

	markClean := fmt.Sprintf(
		"UPDATE %s SET dirty = ?, applied_at = ? WHERE version = ?",
		table,
	)
	if err := session.Query(
		markClean,
		false,
		time.Now().UTC(),
		migration.Version,
	).WithContext(ctx).Consistency(gocql.Quorum).Exec(); err != nil {
		return fmt.Errorf("mark migration V%03d clean: %w", migration.Version, err)
	}

	return nil
}

func loadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "cql")
	if err != nil {
		return nil, fmt.Errorf("read embedded Cassandra migrations: %w", err)
	}

	migrations := make([]Migration, 0, len(entries))
	versions := map[int]string{}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cql") {
			continue
		}

		version, name, err := parseMigrationFilename(entry.Name())
		if err != nil {
			return nil, err
		}
		if previous, exists := versions[version]; exists {
			return nil, fmt.Errorf(
				"duplicate migration version V%03d in %s and %s",
				version,
				previous,
				entry.Name(),
			)
		}

		content, err := migrationFiles.ReadFile(filepath.ToSlash(filepath.Join("cql", entry.Name())))
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		sum := sha256.Sum256(content)
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     name,
			Filename: entry.Name(),
			Checksum: hex.EncodeToString(sum[:]),
			Content:  string(content),
		})
		versions[version] = entry.Name()
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})
	return migrations, nil
}

func parseMigrationFilename(filename string) (int, string, error) {
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	parts := strings.SplitN(base, "__", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "V") {
		return 0, "", fmt.Errorf(
			"invalid migration filename %q; expected V001__description.cql",
			filename,
		)
	}

	version, err := strconv.Atoi(strings.TrimPrefix(parts[0], "V"))
	if err != nil || version <= 0 {
		return 0, "", fmt.Errorf("invalid migration version in %q", filename)
	}

	name := strings.TrimSpace(strings.ReplaceAll(parts[1], "_", " "))
	if name == "" {
		return 0, "", fmt.Errorf("migration %q has no description", filename)
	}
	return version, name, nil
}

func validateIdentifier(value string) error {
	for index, r := range value {
		valid := r == '_' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(index > 0 && r >= '0' && r <= '9')
		if !valid {
			return fmt.Errorf("%q is not a valid unquoted CQL identifier", value)
		}
	}
	return nil
}

// splitCQLStatements splits ordinary migration files without requiring cqlsh.
// It understands line comments, block comments and single-quoted CQL strings.
func splitCQLStatements(content string) ([]string, error) {
	var (
		statements []string
		current    strings.Builder
		inSingle   bool
		inLine     bool
		inBlock    bool
	)

	runes := []rune(content)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		var next rune
		if i+1 < len(runes) {
			next = runes[i+1]
		}

		if inLine {
			if r == '\n' {
				inLine = false
				current.WriteRune(r)
			}
			continue
		}
		if inBlock {
			if r == '*' && next == '/' {
				inBlock = false
				i++
			}
			continue
		}

		if !inSingle && r == '-' && next == '-' {
			inLine = true
			i++
			continue
		}
		if !inSingle && r == '/' && next == '*' {
			inBlock = true
			i++
			continue
		}

		if r == '\'' {
			current.WriteRune(r)
			if inSingle && next == '\'' {
				current.WriteRune(next)
				i++
				continue
			}
			inSingle = !inSingle
			continue
		}

		if !inSingle && r == ';' {
			statement := strings.TrimSpace(current.String())
			if statement != "" {
				statements = append(statements, statement)
			}
			current.Reset()
			continue
		}

		current.WriteRune(r)
	}

	if inSingle {
		return nil, errors.New("unterminated single-quoted string")
	}
	if inBlock {
		return nil, errors.New("unterminated block comment")
	}

	if tail := strings.TrimSpace(current.String()); tail != "" {
		statements = append(statements, tail)
	}
	return statements, nil
}
