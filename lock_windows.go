package main

import "sync"

// Windows is supported only for development tests. Production requires Linux.
var testLock sync.Mutex

func lockState(path string) (func(), error) {
	testLock.Lock()
	return testLock.Unlock, nil
}
