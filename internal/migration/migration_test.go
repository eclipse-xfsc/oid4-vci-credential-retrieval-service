package migration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseMigrationFilename(t *testing.T) {
	version, name, err := parseMigrationFilename("V012__add_credentials_index.cql")
	require.NoError(t, err)
	require.Equal(t, 12, version)
	require.Equal(t, "add credentials index", name)
}

func TestSplitCQLStatements(t *testing.T) {
	content := `
-- comment
CREATE TABLE sample (
	id text PRIMARY KEY,
	value text
);

/* block comment */
INSERT INTO sample (id, value) VALUES ('1', 'a; b');
`
	statements, err := splitCQLStatements(content)
	require.NoError(t, err)
	require.Len(t, statements, 2)
	require.Contains(t, statements[1], "'a; b'")
}
