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

	core, err := runner.New(clientCfg)
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
