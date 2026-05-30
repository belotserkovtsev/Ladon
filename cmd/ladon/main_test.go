package main

import (
	"testing"

	"github.com/belotserkovtsev/ladon/internal/config"
	"github.com/belotserkovtsev/ladon/internal/engine"
)

// TestApplyConfigFile_PromoteThreshold pins the scorer-threshold overlay: a
// positive promote_threshold from the file wins, and with it unset the engine
// default survives untouched.
func TestApplyConfigFile_PromoteThreshold(t *testing.T) {
	def := engine.Defaults("x.log").Scorer.PromoteThreshold

	cases := []struct {
		name    string
		promote int
		want    int
	}{
		{"promote_threshold set", 70, 70},
		{"unset — engine default kept", 0, def},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := engine.Defaults("x.log")
			f := &config.File{}
			f.Scorer.PromoteThreshold = tc.promote

			applyConfigFile(&cfg, f)

			if cfg.Scorer.PromoteThreshold != tc.want {
				t.Errorf("PromoteThreshold = %d, want %d", cfg.Scorer.PromoteThreshold, tc.want)
			}
		})
	}
}
