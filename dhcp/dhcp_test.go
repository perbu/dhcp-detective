package dhcp

import (
	"testing"
	"time"
)

func TestState_Disco(t *testing.T) {
	s, err := New("eth0")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = s.Disco(5 * time.Second)
	if err != nil {
		t.Fatalf("Disco: %v", err)
	}

}
