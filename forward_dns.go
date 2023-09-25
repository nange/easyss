package easyss

import (
	"github.com/miekg/dns"
	"github.com/nange/easyss/v2/log"
)

func NewDNSForwardServer(dnsServer string) *dns.Server {
	srv := &dns.Server{Addr: ":53", Net: "udp"}

	c := &dns.Client{Timeout: DefaultDNSTimeout, UDPSize: 8192}
	srv.Handler = dns.HandlerFunc(func(writer dns.ResponseWriter, msg *dns.Msg) {
		if len(msg.Question) > 0 {
			log.Info("[DNS_FORWARD]", "domain", msg.Question[0].Name)
		}

		r, _, err := c.Exchange(msg, dnsServer)
		if err != nil {
			log.Error("[DNS_FORWARD] exchange", "err", err)
			return
		}

		if err := writer.WriteMsg(r); err != nil {
			log.Error("[DNS_FORWARD] write msg back", "err", err)
		}
	})

	return srv
}

func (ss *Easyss) LocalDNSForward() {
	server := NewDNSForwardServer(ss.DirectDNSServer())
	ss.SetForwardDNSServer(server)

	log.Info("[DNS_FORWARD] starting local dns forward server at :53")
	if err := server.ListenAndServe(); err != nil {
		log.Warn("[DNS_FORWARD] local forward server", "err", err)
	}
}
