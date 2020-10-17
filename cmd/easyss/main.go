package main

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/dialog"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
	"github.com/nange/easyss"
	log "github.com/sirupsen/logrus"
)

var (
	ss      *easyss.Easyss
	mu      sync.Mutex
	logFile string
	logF    *os.File
)


func main() {
	a := app.New()
	w := a.NewWindow("Easyss")
	w.SetFullScreen(false)
	w.SetContent(widget.NewVBox(
		newMainForm(w),
	))
	a.Settings().SetTheme(theme.DarkTheme())

	w.ShowAndRun()
}

func newMainForm(w fyne.Window) *widget.Form {
	host := widget.NewEntry()
	host.SetPlaceHolder("server host addr")
	serverPort := widget.NewEntry()
	serverPort.SetPlaceHolder("server port")
	localPort := widget.NewEntry()
	localPort.SetPlaceHolder("local server port")
	localPort.SetText("2080")
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("password")
	method := widget.NewEntry()
	method.SetPlaceHolder("aes-256-gcm, chacha20-poly1305")
	method.SetText("chacha20-poly1305")
	timeout := widget.NewEntry()
	timeout.SetPlaceHolder("timeout, default 60s")
	timeout.SetText("60")

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Host", Widget: host},
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
					host.Enable()
					serverPort.Enable()
					localPort.Enable()
					password.Enable()
					method.Enable()
					timeout.Enable()
					showInfo(w, "Easyss stoped!")
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
				b := make([]byte, 64)
				_, err := logF.ReadAt(b, 0)
				if err != nil {
					showErrorInfo(w, err)
					return
				}
				showInfo(w, string(b))
				showInfo(w, "Easyss already started!")
				return
			}

			var err error
			if logFile == "" {
				filesDir := os.Getenv("FILESDIR")
				esDir := filepath.Join(filesDir, "easyss")
				if err := os.MkdirAll(esDir, 0777); err != nil {
					showErrorInfo(w, err)
					return
				}
				logFile = filepath.Join(esDir, "easyss.log")
				logF, err = os.OpenFile(logFile, os.O_RDWR|os.O_CREATE, 0666)
				if err != nil {
					showErrorInfo(w, err)
					return
				}

				log.SetOutput(logF)
			}

			defer func() {
				if err != nil {
					showErrorInfo(w, err)
					return
				}
				showInfo(w, "Easyss started!")
				host.Disable()
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
			ss, err = easyss.New(&easyss.Config{
				Server:     host.Text,
				ServerPort: int(serverPortInt),
				LocalPort:  int(localPortInt),
				Password:   password.Text,
				Method:     method.Text,
				Timeout:    int(timeoutInt),
			})
			if err != nil {
				log.Errorf("new easyss:%v", err)
				showErrorInfo(w, err)
				return
			}
			if err := StartEasyss(ss); err != nil {
				log.Errorf("start easyss failed:%v", err)
				showErrorInfo(w, err)
			}
		},
	}
	form.CancelText = "Stop"
	form.SubmitText = "Start"

	return form
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
