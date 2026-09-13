package mocks

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/connection"
	"github.com/gocql/gocql"
)

// Database is a lightweight in-memory mock for the Cassandra adapter. QueryFunc
// can inspect CQL and bound values and return a scripted query/iterator.
type Database struct {
	mu        sync.Mutex
	ClosedVal bool
	Calls     []QueryCall
	QueryFunc func(stmt string, values ...interface{}) connection.QueryInterface
}

type QueryCall struct {
	Statement string
	Values    []interface{}
}

func (d *Database) Query(stmt string, values ...interface{}) connection.QueryInterface {
	d.mu.Lock()
	d.Calls = append(d.Calls, QueryCall{Statement: stmt, Values: append([]interface{}(nil), values...)})
	d.mu.Unlock()
	if d.QueryFunc != nil {
		return d.QueryFunc(stmt, values...)
	}
	return &Query{}
}

func (d *Database) Closed() bool { return d.ClosedVal }
func (d *Database) Close()       { d.ClosedVal = true }

// Query scripts Exec and iterator behaviour without requiring gocql internals.
type Query struct {
	ExecErr error
	Rows    [][]interface{}
}

func (q *Query) Scan(...interface{}) error                               { return nil }
func (q *Query) Exec() error                                             { return q.ExecErr }
func (q *Query) WithContext(context.Context) connection.QueryInterface   { return q }
func (q *Query) Consistency(gocql.Consistency) connection.QueryInterface { return q }
func (q *Query) Iter() connection.IterInterface                          { return &Iterator{Rows: q.Rows} }

// Iterator assigns scripted row values to Scan destinations using reflection.
type Iterator struct {
	Rows [][]interface{}
	pos  int
	Err  error
}

func (i *Iterator) Scan(dest ...interface{}) bool {
	if i.pos >= len(i.Rows) {
		return false
	}
	row := i.Rows[i.pos]
	i.pos++
	if len(row) != len(dest) {
		panic(fmt.Sprintf("mock iterator: row has %d values, Scan has %d destinations", len(row), len(dest)))
	}
	for n := range row {
		d := reflect.ValueOf(dest[n])
		if d.Kind() != reflect.Ptr || d.IsNil() {
			panic("mock iterator: destination must be a non-nil pointer")
		}
		v := reflect.ValueOf(row[n])
		if !v.IsValid() {
			d.Elem().Set(reflect.Zero(d.Elem().Type()))
			continue
		}
		if v.Type().AssignableTo(d.Elem().Type()) {
			d.Elem().Set(v)
		} else if v.Type().ConvertibleTo(d.Elem().Type()) {
			d.Elem().Set(v.Convert(d.Elem().Type()))
		} else {
			panic(fmt.Sprintf("mock iterator: cannot assign %T to %s", row[n], d.Elem().Type()))
		}
	}
	return true
}

func (i *Iterator) Close() error { return i.Err }
