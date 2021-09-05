package store

import (
	"context"
	"errors"
	"sync"

	"github.com/superseriousbusiness/oauth2/pkg/models"
)

// InMemClientStore returns a ClientStore that uses a simple in-memory implementation.
func InMemClientStore() ClientStore {
	return &clientStore{
		data: make(map[string]models.Client),
	}
}

// ClientStore represents a storage method for oauth client information.
type ClientStore interface {
	GetByID(ctx context.Context, id string) (models.Client, error)
	Set(ctx context.Context, id string, cli models.Client) error
	Delete(ctx context.Context, id string) error
}

type clientStore struct {
	sync.RWMutex
	data map[string]models.Client
}

func (cs *clientStore) GetByID(ctx context.Context, id string) (models.Client, error) {
	cs.RLock()
	defer cs.RUnlock()

	if c, ok := cs.data[id]; ok {
		return c, nil
	}
	return nil, errors.New("not found")
}

func (cs *clientStore) Set(ctx context.Context, id string, cli models.Client) error {
	cs.Lock()
	defer cs.Unlock()

	cs.data[id] = cli
	return nil
}

func (cs *clientStore) Delete(ctx context.Context, id string) error {
	delete(cs.data, id)
	return nil
}
