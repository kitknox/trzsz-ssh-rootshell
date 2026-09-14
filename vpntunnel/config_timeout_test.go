package vpntunnel

import (
	"fmt"
	"testing"
	"time"
)

func TestConnectTimeoutConfig(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		want        time.Duration
	}{
		{"legacy", "", 30 * time.Second},
		{"zero", `,"connectTimeoutSec":0`, 30 * time.Second},
		{"negative", `,"connectTimeoutSec":-1`, 30 * time.Second},
		{"tooLarge", `,"connectTimeoutSec":121`, 30 * time.Second},
		{"minimum", `,"connectTimeoutSec":1`, time.Second},
		{"custom", `,"connectTimeoutSec":5`, 5 * time.Second},
		{"maximum", `,"connectTimeoutSec":120`, 120 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfig(fmt.Sprintf(`{"transportType":"tssh"%s}`, tc.field))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.connectTimeout(); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
