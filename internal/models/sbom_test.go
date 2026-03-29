package models

import (
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestSBOM_TableName(t *testing.T) {
	s := SBOM{}
	if s.TableName() != "sboms" {
		t.Errorf("Expected table name 'sboms', got '%s'", s.TableName())
	}
}

func TestSBOM_BeforeCreate(t *testing.T) {
	s := &SBOM{}
	tx := &gorm.DB{}

	err := s.BeforeCreate(tx)
	if err != nil {
		t.Errorf("BeforeCreate() unexpected error: %v", err)
	}

	if s.ID == uuid.Nil {
		t.Error("BeforeCreate() should set UUID when nil")
	}
}

func TestSBOM_Validate(t *testing.T) {
	tests := []struct {
		name    string
		sbom    *SBOM
		wantErr bool
	}{
		{
			name: "valid SPDX SBOM",
			sbom: &SBOM{
				Name:   "test-sbom",
				Format: "SPDX",
			},
			wantErr: false,
		},
		{
			name: "valid CycloneDX SBOM",
			sbom: &SBOM{
				Name:   "test-sbom",
				Format: "CycloneDX",
			},
			wantErr: false,
		},
		{
			name: "invalid SBOM - empty name",
			sbom: &SBOM{
				Name:   "",
				Format: "SPDX",
			},
			wantErr: true,
		},
		{
			name: "invalid SBOM - invalid format",
			sbom: &SBOM{
				Name:   "test-sbom",
				Format: "Invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sbom.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("SBOM.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSBOM_IsSPDX(t *testing.T) {
	tests := []struct {
		name string
		sbom *SBOM
		want bool
	}{
		{
			name: "is SPDX",
			sbom: &SBOM{Format: "SPDX"},
			want: true,
		},
		{
			name: "is not SPDX",
			sbom: &SBOM{Format: "CycloneDX"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sbom.IsSPDX(); got != tt.want {
				t.Errorf("SBOM.IsSPDX() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSBOM_IsCycloneDX(t *testing.T) {
	tests := []struct {
		name string
		sbom *SBOM
		want bool
	}{
		{
			name: "is CycloneDX",
			sbom: &SBOM{Format: "CycloneDX"},
			want: true,
		},
		{
			name: "is not CycloneDX",
			sbom: &SBOM{Format: "SPDX"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sbom.IsCycloneDX(); got != tt.want {
				t.Errorf("SBOM.IsCycloneDX() = %v, want %v", got, tt.want)
			}
		})
	}
}
