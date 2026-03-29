package models

import (
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestPackage_TableName(t *testing.T) {
	p := Package{}
	if p.TableName() != "packages" {
		t.Errorf("Expected table name 'packages', got '%s'", p.TableName())
	}
}

func TestPackage_BeforeCreate(t *testing.T) {
	p := &Package{}
	tx := &gorm.DB{}

	err := p.BeforeCreate(tx)
	if err != nil {
		t.Errorf("BeforeCreate() unexpected error: %v", err)
	}

	if p.ID == uuid.Nil {
		t.Error("BeforeCreate() should set UUID when nil")
	}
}

func TestPackage_BeforeCreate_ExistingUUID(t *testing.T) {
	existingID := uuid.New()
	p := &Package{ID: existingID}
	tx := &gorm.DB{}

	err := p.BeforeCreate(tx)
	if err != nil {
		t.Errorf("BeforeCreate() unexpected error: %v", err)
	}

	if p.ID != existingID {
		t.Error("BeforeCreate() should not change existing UUID")
	}
}

func TestPackage_Validate(t *testing.T) {
	tests := []struct {
		name    string
		pkg     *Package
		wantErr bool
	}{
		{
			name: "valid package",
			pkg: &Package{
				Name: "test-package",
			},
			wantErr: false,
		},
		{
			name: "invalid package - empty name",
			pkg: &Package{
				Name: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pkg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Package.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPackage_HasPURL(t *testing.T) {
	tests := []struct {
		name string
		pkg  *Package
		want bool
	}{
		{
			name: "has PURL",
			pkg: &Package{
				PURL: strPtr("pkg:npm/test-package@1.0.0"),
			},
			want: true,
		},
		{
			name: "PURL is nil",
			pkg: &Package{
				PURL: nil,
			},
			want: false,
		},
		{
			name: "PURL is empty",
			pkg: &Package{
				PURL: strPtr(""),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pkg.HasPURL(); got != tt.want {
				t.Errorf("Package.HasPURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
