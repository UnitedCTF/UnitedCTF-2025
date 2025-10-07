package utils

import "sync"

func WithLock(f func(), l *sync.Mutex) {
	defer (*l).Unlock()

	(*l).Lock()
	f()
}

func WaitAll(fs ...func()) {
	var wg sync.WaitGroup
	wg.Add(len(fs))
	for _, f := range fs {
		go func() {
			f()
			wg.Done()
		}()
	}
	wg.Wait()
}
