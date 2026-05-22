package loki

import (
	"strings"
	"testing"
)

func TestSource_Name(t *testing.T) {
	s := &Source{}
	if s.Name() != "Loki" {
		t.Errorf("expected Name()=Loki, got %q", s.Name())
	}
}

func TestSource_Description(t *testing.T) {
	s := &Source{}
	if s.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestSource_Instruction(t *testing.T) {
	s := &Source{}
	instr := s.Instruction()
	if instr == "" {
		t.Error("expected non-empty instruction")
	}
	if !strings.Contains(instr, "LogQL") {
		t.Error("expected Loki instruction to contain LogQL references")
	}
}
