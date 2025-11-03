package core

import (
	"sync"
	"time"
)

type Blacklist struct {
	tokens map[string]time.Time
	mu     sync.RWMutex
}

func NewBlacklist() *Blacklist {
	return &Blacklist{
		tokens: make(map[string]time.Time),
	}
}

func (b *Blacklist) Add(token string, expiry time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[token] = expiry
}

func (b *Blacklist) IsRevoked(token string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	expiry, exists := b.tokens[token]
	if !exists {
		return false
	}

	// Если токен просрочен, удаляем его из blacklist
	if time.Now().After(expiry) {
		b.mu.RUnlock()
		b.mu.Lock()
		delete(b.tokens, token)
		b.mu.Unlock()
		b.mu.RLock()
		return false
	}

	return true
}
