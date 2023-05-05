package cipherstream

import (
	"errors"
)

var (
	ErrFINRSTStream = errors.New("receive FIN_RST_STREAM frame")
	ErrACKRSTStream = errors.New("receive ACK_RST_STREAM frame")
	ErrTimeout      = errors.New("net: io timeout error")
	ErrPayloadSize  = errors.New("payload size is invalid")
	ErrPingHook     = errors.New("ping hook error")
)
