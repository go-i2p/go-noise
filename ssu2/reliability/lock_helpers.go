package reliability

import "sync"

func withRLock[T any](mu *sync.RWMutex, fn func() T) T {
	mu.RLock()
	defer mu.RUnlock()
	return fn()
}

func withLock[T any](mu *sync.Mutex, fn func() T) T {
	mu.Lock()
	defer mu.Unlock()
	return fn()
}

func withLock2[T1, T2 any](mu *sync.Mutex, fn func() (T1, T2)) (T1, T2) {
	mu.Lock()
	defer mu.Unlock()
	return fn()
}
