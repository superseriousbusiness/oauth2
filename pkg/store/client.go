package store

import (
	"context"
	"errors"
	"sync"

	"github.com/superseriousbusiness/oauth2/pkg/models"
)

// NewClientStore create client store
func NewClientStore() ClientStore {
	return &clientStore{
		data: make(map[string]models.ClientInfo),
	}
}

// ClientStore client information store
type ClientStore interface {
	GetByID(ctx context.Context, id string) (models.ClientInfo, error)
	Set(ctx context.Context, id string, cli models.ClientInfo) error
	Delete(ctx context.Context, id string) error
}

// ClientStore client information store
type clientStore struct {
	sync.RWMutex
	data map[string]models.ClientInfo
}

// GetByID according to the ID for the client information
func (cs *clientStore) GetByID(ctx context.Context, id string) (models.ClientInfo, error) {
	cs.RLock()
	defer cs.RUnlock()

	if c, ok := cs.data[id]; ok {
		return c, nil
	}
	return nil, errors.New("not found")
}

// Set set client information
func (cs *clientStore) Set(ctx context.Context, id string, cli models.ClientInfo) error {
	cs.Lock()
	defer cs.Unlock()

	cs.data[id] = cli
	return nil
}

func (cs *clientStore) Delete(ctx context.Context, id string) error {
	delete(cs.data, id)
	return nil
}
