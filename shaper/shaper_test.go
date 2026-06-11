package shaper

import (
	"testing"

	"github.com/nange/easyss/v3/protocol"
)

func TestBuildPaddingFrames(t *testing.T) {
	tests := []struct {
		name      string
		totalSize int
	}{
		{"tiny", 32},
		{"small", 256},
		{"medium", 700},
		{"large", 1600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frames := BuildPaddingFrames(tt.totalSize)
			if len(frames) > 1 {
				t.Fatalf("expected at most 1 padding frame, got %d", len(frames))
			}
			if len(frames) == 1 {
				if frames[0].Type != protocol.FramePADDING {
					t.Fatalf("expected PADDING frame, got %d", frames[0].Type)
				}
				if int(frames[0].Length) == 0 {
					t.Fatal("padding frame length is 0")
				}
			}
		})
	}
}
