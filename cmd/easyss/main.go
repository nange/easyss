package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/nange/easyss"
	log "github.com/sirupsen/logrus"
)

var (
	ss      *easyss.Easyss
	mu      sync.Mutex
	esDir   string
	logFile string
	logF    *os.File
)

const (
	confFilename = "config.json"
	logFilename  = "easyss.log"
)

func main() {
	a := app.New()
	w := a.NewWindow("Easyss")

	w.CenterOnScreen()
	w.Resize(fyne.NewSize(400, 400))
	w.SetFullScreen(false)
	box := container.NewVBox(newMainForm(w), showLogsContainer())
	w.SetContent(box)

	a.Settings().SetTheme(theme.DarkTheme())

	w.ShowAndRun()
}

func newMainForm(w fyne.Window) *widget.Form {
	mu.Lock()
	defer mu.Unlock()

	esDir = easyssPath()
	if logFile == "" {
		var err error
		if err := os.MkdirAll(esDir, 0777); err != nil {
			showErrorInfo(w, err)
		}

		logFile = filepath.Join(esDir, logFilename)
		logF, err = os.OpenFile(logFile, os.O_RDWR|os.O_CREATE, 0666)
		if err != nil {
			showErrorInfo(w, err)
		}
		log.SetOutput(logF)
	}

	conf, err := loadConfFromFile(filepath.Join(esDir, confFilename))
	if err != nil {
		log.Warnf("load config from file err:%v", err)
	}

	server := widget.NewEntry()
	server.SetPlaceHolder("server host addr")
	server.SetText(conf.Server)

	serverPort := widget.NewEntry()
	serverPort.SetPlaceHolder("server port")
	serverPort.SetText("9999")
	if conf.ServerPort != 0 {
		serverPort.SetText(fmt.Sprint(conf.ServerPort))
	}

	localPort := widget.NewEntry()
	localPort.SetPlaceHolder("local server port")
	localPort.SetText("2080")
	if conf.LocalPort != 0 {
		localPort.SetText(fmt.Sprint(conf.LocalPort))
	}

	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("password")
	password.SetText(conf.Password)

	method := widget.NewEntry()
	method.SetPlaceHolder("aes-256-gcm, chacha20-poly1305")
	method.SetText("chacha20-poly1305")
	if conf.Method != "" {
		method.SetText(conf.Method)
	}

	timeout := widget.NewEntry()
	timeout.SetPlaceHolder("timeout, default 60s")
	timeout.SetText("60")
	if conf.Timeout != 0 {
		timeout.SetText(fmt.Sprint(conf.Timeout))
	}

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Server", Widget: server},
			{Text: "Server Port", Widget: serverPort},
			{Text: "Local Port", Widget: localPort},
			{Text: "Password", Widget: password},
			{Text: "Method", Widget: method},
			{Text: "Timeout", Widget: timeout},
		},
		OnCancel: func() {
			cnf := dialog.NewConfirm("Stop", "Continue to stop?", func(b bool) {
				mu.Lock()
				defer mu.Unlock()
				if b && ss != nil {
					ss.Close()
					ss = nil
					server.Enable()
					serverPort.Enable()
					localPort.Enable()
					password.Enable()
					method.Enable()
					timeout.Enable()
					showInfo(w, "Easyss stopped!")
				}
				if logF != nil {
					logF.Close()
				}
			}, w)
			cnf.SetDismissText("No")
			cnf.SetConfirmText("Yes")
			cnf.Show()
		},
		OnSubmit: func() {
			mu.Lock()
			defer mu.Unlock()
			if ss != nil {
				showInfo(w, "Easyss already started!")
				return
			}

			var err error
			defer func() {
				if err != nil {
					showErrorInfo(w, err)
					return
				}
				showInfo(w, "Easyss started!")
				server.Disable()
				serverPort.Disable()
				localPort.Disable()
				password.Disable()
				method.Disable()
				timeout.Disable()
			}()

			prog := showProcess(w)
			defer prog.Hide()

			serverPortInt, err := strconv.ParseInt(serverPort.Text, 10, 64)
			if err != nil {
				log.Errorf("server port is invalid")
				showErrorInfo(w, err)
				return
			}
			localPortInt, err := strconv.ParseInt(localPort.Text, 10, 64)
			if err != nil {
				log.Errorf("local port is invalid")
				showErrorInfo(w, err)
				return
			}
			timeoutInt, err := strconv.ParseInt(timeout.Text, 10, 64)
			if err != nil {
				log.Errorf("timeout is invalid")
				showErrorInfo(w, err)
				return
			}
			conf := &easyss.Config{
				Server:     server.Text,
				ServerPort: int(serverPortInt),
				LocalPort:  int(localPortInt),
				Password:   password.Text,
				Method:     method.Text,
				Timeout:    int(timeoutInt),
			}
			ss, _ = easyss.New(conf)
			if err := StartEasyss(ss); err != nil {
				log.Errorf("start easyss failed:%v", err)
				showErrorInfo(w, err)
			}
			if err := writeConfToFile(filepath.Join(esDir, confFilename), *conf); err != nil {
				log.Errorf("write config to file err:%v", err)
				showErrorInfo(w, err)
			}
		},
	}
	form.CancelText = "Stop"
	form.SubmitText = "Start"

	return form
}

func showLogsContainer() *fyne.Container {
	e := widget.NewMultiLineEntry()
	e.Disable()

	hide := true
	btn := widget.NewButton("Show Logs", func() {
		if !hide {
			e.SetText("")
			hide = true
			return
		}

		mu.Lock()
		lp := logFile
		mu.Unlock()

		str, err := readTailOfLogs(lp)
		if err != nil {
			log.Errorf("read tail of logs: %v", err)
			return
		}
		e.SetText(str)

		hide = false
	})

	grid := container.NewGridWrap(fyne.NewSize(400, 200), e)

	box := container.NewVBox(btn, grid)
	return box
}

func StartEasyss(ss *easyss.Easyss) error {
	log.Infof("on mobile arch, we should ignore systray")

	if err := ss.InitTcpPool(); err != nil {
		log.Errorf("init tcp pool error:%v", err)
		return err
	}

	go ss.Local()     // start local server
	go ss.HttpLocal() // start http proxy server

	return nil
}

func showProcess(w fyne.Window) *dialog.ProgressDialog {
	prog := dialog.NewProgress("Processing", "Starting...", w)

	go func() {
		num := 0.0
		for num < 1.0 {
			time.Sleep(20 * time.Millisecond)
			prog.SetValue(num)
			num += 0.01
		}

		prog.SetValue(1)
	}()

	prog.Show()
	return prog
}

func showErrorInfo(w fyne.Window, err error) {
	dialog.ShowError(err, w)
}

func showInfo(w fyne.Window, info string) {
	dialog.ShowInformation("Info", info, w)
}

func loadConfFromFile(file string) (easyss.Config, error) {
	f, err := os.Open(file)
	if err != nil {
		return easyss.Config{}, err
	}
	defer f.Close()

	var conf easyss.Config
	if err := json.NewDecoder(f).Decode(&conf); err != nil {
		return easyss.Config{}, err
	}
	return conf, nil
}

func easyssPath() string {
	filesDir := os.Getenv("FILESDIR")
	return filepath.Join(filesDir, "easyss")
}

func writeConfToFile(file string, conf easyss.Config) error {
	b, err := json.Marshal(conf)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, b, 0666)
}

func readTailOfLogs(lp string) (string, error) {
	size := int64(1024)

	lf, err := os.Open(lp)
	if err != nil {
		return "", err
	}
	defer lf.Close()

	st, err := lf.Stat()
	if err != nil {
		return "", err
	}
	if st.Size() > size {
		if _, err = lf.Seek(st.Size()-size, io.SeekStart); err != nil {
			return "", err
		}
	}

	reader := bufio.NewReader(lf)
	// drop the first line, since maybe it is incomplete.
	_, _, err = reader.ReadLine()
	if err != nil {
		return "", err
	}

	b, err := io.ReadAll(reader)

	return string(b), err
}
