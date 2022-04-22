package teststore

import (
	"github.com/serhiimazurok/go-demo/internal/app/model"
	"github.com/serhiimazurok/go-demo/internal/app/store"
)

type Store struct {
	userRepository *UserRepository
}

func New() *Store {
	return &Store{}
}

func (s *Store) User() store.UserRepository {
	if s.userRepository == nil {
		s.userRepository = &UserRepository{
			store: s,
			users: make(map[int]*model.User),
		}
	}

	return s.userRepository
}
