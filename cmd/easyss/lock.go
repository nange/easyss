package main

import "errors"

// errAnotherInstance reports that the singleton lock is held by another
// running instance, as opposed to a failure to create the lock itself. The
// startup path exits 0 on it (a second launch is a no-op), while the tray's
// post-update recovery path only warns: the app keeps running without the
// lock rather than disappearing.
var errAnotherInstance = errors.New("another easyss instance is already running")
