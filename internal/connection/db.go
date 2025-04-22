package connection

import (
	"context"

	logPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/gocql/gocql"
)

type SessionInterface interface {
	Query(string, ...interface{}) QueryInterface
	Closed() bool
	Close()
}

type QueryInterface interface {
	Scan(...interface{}) error
	Exec() error
	Raw() *gocql.Query
	WithContext(ctx context.Context) QueryInterface
	Consistency(consistency gocql.Consistency) QueryInterface
}

type Session struct {
	session *gocql.Session
}

func (s *Session) Closed() bool {
	return s.session.Closed()
}

func (s *Session) Close() {
	s.session.Close()
}

func (s *Session) Query(stmt string, values ...interface{}) QueryInterface {
	return NewQuery(s.session.Query(stmt, values...))
}

type Query struct {
	query *gocql.Query
}

func (q *Query) Consistency(consistency gocql.Consistency) QueryInterface {
	return NewQuery(q.query.Consistency(consistency))
}

func (q *Query) Exec() error {
	return q.query.Exec()
}

func (q *Query) Raw() *gocql.Query {
	return q.query
}

// Scan wraps the query's Scan method
func (q *Query) Scan(dest ...interface{}) error {
	return q.query.Scan(dest...)
}

func (q *Query) WithContext(c context.Context) QueryInterface {
	return NewQuery(q.query.WithContext(c))
}

func NewSession(session *gocql.Session) SessionInterface {
	return &Session{session: session}
}

// NewQuery instantiates a new Query
func NewQuery(query *gocql.Query) QueryInterface {
	return &Query{query}
}

func Connection(logger *logPkg.Logger) (SessionInterface, error) {
	cassandraConfig := config.CurrentCredentialRetrievalConfig.Cassandra

	host := cassandraConfig.Host
	keyspace := cassandraConfig.KeySpace

	logger.Info("connecting db", "KEYSPACE", keyspace, "HOSTS", host)
	cluster := gocql.NewCluster(host)

	if cassandraConfig.User != "" && cassandraConfig.Password != "" {
		cluster.Authenticator = gocql.PasswordAuthenticator{
			Username: cassandraConfig.User,
			Password: cassandraConfig.Password,
		}
	}

	cluster.Keyspace = keyspace
	cluster.Consistency = gocql.Quorum
	cluster.ProtoVersion = 4

	session, err := cluster.CreateSession()
	if err != nil {
		return nil, err
	}

	if err != nil {
		defer logger.Info("Connection to database failed")
		logger.Error(err, "No connection possible")
		return nil, err
	} else {
		logger.Info("Connection to database successful")
	}

	return NewSession(session), err
}
