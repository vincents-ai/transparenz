package models

import (
	"encoding/json"
	"testing"
)

func TestJSONB_Value(t *testing.T) {
	tests := []struct {
		name    string
		jsonb   JSONB
		want    []byte
		wantErr bool
	}{
		{
			name:  "nil JSONB",
			jsonb: nil,
			want:  nil,
		},
		{
			name:  "empty JSONB",
			jsonb: JSONB{},
			want:  []byte("{}"),
		},
		{
			name: "JSONB with data",
			jsonb: JSONB{
				"key": "value",
				"num": 123,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.jsonb.Value()
			if (err != nil) != tt.wantErr {
				t.Errorf("JSONB.Value() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil {
				if string(got.([]byte)) != string(tt.want) {
					t.Errorf("JSONB.Value() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestJSONB_Scan(t *testing.T) {
	tests := []struct {
		name    string
		value   interface{}
		want    JSONB
		wantErr bool
	}{
		{
			name:  "nil value",
			value: nil,
			want:  nil,
		},
		{
			name:  "valid JSON bytes",
			value: []byte(`{"key":"value","num":123}`),
			want: JSONB{
				"key": "value",
				"num": float64(123),
			},
		},
		{
			name:    "invalid JSON bytes",
			value:   []byte(`{invalid}`),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "non-bytes type",
			value:   12345,
			want:    nil,
			wantErr: true,
		},
		{
			name:  "empty JSON object",
			value: []byte("{}"),
			want:  JSONB{},
		},
		{
			name:  "nested JSON object",
			value: []byte(`{"outer":{"inner":"value"}}`),
			want: JSONB{
				"outer": map[string]interface{}{
					"inner": "value",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &JSONB{}
			err := j.Scan(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("JSONB.Scan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.value != nil {
				if tt.value == nil {
					if *j != nil {
						t.Errorf("JSONB.Scan() = %v, want nil", *j)
					}
				} else {
					gotJSON, _ := json.Marshal(*j)
					wantJSON, _ := json.Marshal(tt.want)
					if string(gotJSON) != string(wantJSON) {
						t.Errorf("JSONB.Scan() = %v, want %v", *j, tt.want)
					}
				}
			}
		})
	}
}
