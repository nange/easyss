package handler

import (
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
)

type PingHandler struct {
}

func NewPingHandler() *PingHandler {
	return &PingHandler{}
}

func (h *PingHandler) Handle(dr *crypto.DecryptedReader, s2c shaper.Shaper, target string) error {
	frame, err := dr.ReadFrame()
	if err != nil {
		return err
	}

	switch frame.Type {
	case protocol.FrameDATA:
		dataFrame := protocol.NewFrameDATA(frame.Payload)
		finFrame := protocol.NewFrameFIN()
		_ = s2c.PushFrame(dataFrame)
		_ = s2c.PushFrame(finFrame)
		_ = s2c.Flush()
		log.Debug("[PING_HANDLER] echoed pong")
		return nil
	case protocol.FrameFIN, protocol.FrameRST:
		return nil
	default:
		log.Debug("[PING_HANDLER] unexpected frame type", "type", frame.Type)
		return nil
	}
}
