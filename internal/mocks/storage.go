package mocks

import (
	"context"
	"sync"

	messaging "github.com/eclipse-xfsc/nats-message-library"
)

// StoragePublisher replaces the NATS-backed storage publisher in service tests.
// It records every storage message and can be configured to fail publication.
type StoragePublisher struct {
	mu       sync.Mutex
	Messages []messaging.StorageServiceStoreMessage
	Err      error
}

func (p *StoragePublisher) Publish(_ context.Context, message messaging.StorageServiceStoreMessage) error {
	if p.Err != nil {
		return p.Err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Messages = append(p.Messages, message)
	return nil
}
