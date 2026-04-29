package cipherstream

import (
	"errors"
)

var (
	ErrFINRSTStream = errors.New("receive FIN_RST_STREAM frame")
	ErrACKRSTStream = errors.New("receive ACK_RST_STREAM frame")
	ErrTimeout      = newTimeoutError()
	ErrPayloadSize  = errors.New("payload size is invalid")
)

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "net: io timeout error" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func newTimeoutError() error { return &timeoutError{} }
