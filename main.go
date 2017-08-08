package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: "2006-01-02 15:04:05.000"})
	log.SetLevel(log.InfoLevel)
}

func PrintVersion() {
	const version = "Alpha"
	fmt.Println("easyss version:", version)
}

func main() {
	var configFile, cmdLocal string
	var printVer, debug bool
	var cmdConfig Config

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Server, "s", "", "server address")
	flag.StringVar(&cmdLocal, "b", "", "local address, listen only to this address if specified")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.IntVar(&cmdConfig.LocalPort, "l", 0, "local socks5 proxy port")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.BoolVar(&debug, "d", false, "print debug message")
	flag.BoolVar(&cmdConfig.Auth, "A", false, "one time auth")

	flag.Parse()

	if printVer {
		PrintVersion()
		os.Exit(0)
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	if strings.HasSuffix(cmdConfig.Method, "-auth") {
		log.Debugln("use one time auth")
		cmdConfig.Method = cmdConfig.Method[:len(cmdConfig.Method)-5]
		cmdConfig.Auth = true
	}

	exists, err := FileExists(configFile)
	if !exists || err != nil {
		log.Debugf("config file err:%v", err)

		binDir := path.Dir(os.Args[0])
		configFile = path.Join(binDir, "config.json")

		log.Debugf("config file not found, try config file %s", configFile)
	}

	config, err := ParseConfig(configFile)
	if err != nil {
		config = &cmdConfig
		if !os.IsNotExist(errors.Cause(err)) {
			log.Errorf("error reading %s: %+v", configFile, err)
			os.Exit(1)
		}
	} else {
		UpdateConfig(config, &cmdConfig)
	}

	if config.Method == "" {
		config.Method = "aes-256-gcm"
	}

}

func FileExists(path string) (bool, error) {
	f, err := os.Stat(path)
	if err == nil {
		if stat.Mode()&os.ModeType == 0 {
			return true, nil
		}
		return false, errors.WithStack(errors.New(path + " exists but is not regular file"))
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, errors.WithStack(err)
}

func ConfigValid(config *Config) bool {

}
