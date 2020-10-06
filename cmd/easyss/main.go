package main

import (
	"strconv"

	"fyne.io/fyne/app"
	"fyne.io/fyne/widget"
	"github.com/nange/easyss"
	log "github.com/sirupsen/logrus"
)

var ss *easyss.Easyss

func main() {
	a := app.New()
	w := a.NewWindow("Easyss")
	w.SetFullScreen(false)
	w.SetContent(widget.NewVBox(
		newMainForm(),
	))

	w.ShowAndRun()
}

func newMainForm() *widget.Form {
	host := widget.NewEntry()
	host.SetPlaceHolder("server host addr")
	serverPort := widget.NewEntry()
	serverPort.SetPlaceHolder("server port")
	localPort := widget.NewEntry()
	localPort.SetPlaceHolder("local server port")
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Password")
	method := widget.NewEntry()
	method.SetPlaceHolder("aes-256-gcm, chacha20-poly1305")
	timeout := widget.NewEntry()
	timeout.SetPlaceHolder("timeout, default 60s")

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
			if ss != nil {
				ss.Close()
			}
		},
		OnSubmit: func() {
			if ss != nil {
				log.Info("Easyss already started...")
				return
			}

			var err error
			serverPortInt, err := strconv.ParseInt(serverPort.Text, 10, 64)
			if err != nil {
				log.Errorf("server port is invalid")
				return
			}
			localPortInt, err := strconv.ParseInt(localPort.Text, 10, 64)
			if err != nil {
				log.Errorf("local port is invalid")
				return
			}
			timeoutInt, err := strconv.ParseInt(timeout.Text, 10, 64)
			if err != nil {
				log.Errorf("timeout is invalid")
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
				return
			}
			StartEasyss(ss)
		},
	}
	form.CancelText = "Stop"
	form.SubmitText = "Start"

	return form
}

func StartEasyss(ss *easyss.Easyss) {
	log.Infof("on mobile arch, we should ignore systray")

	if err := ss.InitTcpPool(); err != nil {
		log.Errorf("init tcp pool error:%v", err)
	}

	ss.Local() // start local server
}
