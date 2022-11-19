package internal

import (
	"testing"
)

func TestGetVersion(t *testing.T) {
	if GetVersion().String() != version.String() {
		t.Errorf("GetVersion() = %v, want %v", GetVersion(), version)
	}
}
