package easyss

import (
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func NewDNSForwardServer(dnsServer string) *dns.Server {
	srv := &dns.Server{Addr: ":53", Net: "udp"}

	srv.Handler = dns.HandlerFunc(func(writer dns.ResponseWriter, msg *dns.Msg) {
		c := &dns.Client{Timeout: DefaultUDPTimeout}
		r, _, err := c.Exchange(msg, dnsServer)
		if err != nil {
			log.Errorf("dns exchange err:%s", err.Error())
			return
		}

		if err := writer.WriteMsg(r); err != nil {
			log.Errorf("write dns msg back err:%s", err.Error())
		}
	})

	return srv
}

func (ss *Easyss) LocalDNSForward() error {
	server := NewDNSForwardServer(ss.DirectDNSServer())
	ss.SetForwardDNSServer(server)

	log.Infof("starting local dns forward server at :53")
	err := server.ListenAndServe()
	if err != nil {
		log.Warnf("local dns forward server:%s", err.Error())
	}

	return err
}
