// Package mobile is the gomobile binding for the EasySS client core.
//
// The transport warm-up is no longer exported here: runner.Run dispatches it
// in the background once the core is up (runner.Core.StartWarmUp), unless the
// configuration disables it via transport.disable_warm_up. Host applications
// upgrading this AAR must drop their WarmUp() call accordingly — Start()
// returning already means the warm-up has been dispatched. The "connecting"
// state users previously saw while the binding blocked on the warm-up is
// therefore no longer observable from here.
package mobile

import (
	"fmt"
	"sync"

	"github.com/nange/easyss/v3/client/config"
	sharedconfig "github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/version"
)

var (
	mCore *runner.Core
	mMu   sync.Mutex
)

func Start(cfg *sharedconfig.SimpleConfig) error {
	mMu.Lock()
	defer mMu.Unlock()

	if mCore != nil {
		return fmt.Errorf("already started, call Stop first")
	}

	clientCfg, err := config.BuildSimpleConfig(cfg)
	if err != nil {
		return err
	}

	core, err := runner.Run(clientCfg)
	if err != nil {
		return err
	}
	mCore = core
	return nil
}

func Stop() {
	mMu.Lock()
	defer mMu.Unlock()

	if mCore == nil {
		return
	}

	mCore.Stop()
	mCore = nil
}
func Version() string {
	return version.Tag()
}
