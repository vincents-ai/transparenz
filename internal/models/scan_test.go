package models

import (
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestScan_TableName(t *testing.T) {
	s := Scan{}
	if s.TableName() != "scans" {
		t.Errorf("Expected table name 'scans', got '%s'", s.TableName())
	}
}

func TestScan_BeforeCreate(t *testing.T) {
	s := &Scan{}
	tx := &gorm.DB{}

	err := s.BeforeCreate(tx)
	if err != nil {
		t.Errorf("BeforeCreate() unexpected error: %v", err)
	}

	if s.ID == uuid.Nil {
		t.Error("BeforeCreate() should set UUID when nil")
	}
}

func TestScan_HasVulnerabilities(t *testing.T) {
	tests := []struct {
		name string
		scan *Scan
		want bool
	}{
		{
			name: "has vulnerabilities",
			scan: &Scan{TotalVulnerabilities: 5},
			want: true,
		},
		{
			name: "no vulnerabilities",
			scan: &Scan{TotalVulnerabilities: 0},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scan.HasVulnerabilities(); got != tt.want {
				t.Errorf("Scan.HasVulnerabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScan_GetTotalSeverityCount(t *testing.T) {
	s := &Scan{
		CriticalCount: 2,
		HighCount:     3,
		MediumCount:   4,
		LowCount:      5,
	}

	want := 14
	if got := s.GetTotalSeverityCount(); got != want {
		t.Errorf("Scan.GetTotalSeverityCount() = %v, want %v", got, want)
	}
}

func TestScan_HasCriticalVulnerabilities(t *testing.T) {
	tests := []struct {
		name string
		scan *Scan
		want bool
	}{
		{
			name: "has critical vulnerabilities",
			scan: &Scan{CriticalCount: 1},
			want: true,
		},
		{
			name: "no critical vulnerabilities",
			scan: &Scan{CriticalCount: 0},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scan.HasCriticalVulnerabilities(); got != tt.want {
				t.Errorf("Scan.HasCriticalVulnerabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}
