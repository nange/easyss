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
			log.Errorf("[DNS_FORWARD] exchange err:%s", err.Error())
			return
		}

		if err := writer.WriteMsg(r); err != nil {
			log.Errorf("[DNS_FORWARD] write msg back err:%s", err.Error())
		}
	})

	return srv
}

func (ss *Easyss) LocalDNSForward() {
	server := NewDNSForwardServer(ss.DirectDNSServer())
	ss.SetForwardDNSServer(server)

	log.Infof("[DNS_FORWARD] starting local dns forward server at :53")
	if err := server.ListenAndServe(); err != nil {
		log.Warnf("[DNS_FORWARD] local forward server:%s", err.Error())
	}
}
