package modules

import "sync"

type LogStore struct {
	logs []string
	mu   sync.Mutex
}

func NewLogStore() *LogStore {
	return &LogStore{logs: make([]string, 0)}
}

func (l *LogStore) AddLog(entry string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, entry)
}

func (l *LogStore) GetLogs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.logs...)
}
