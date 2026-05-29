package main

import (
	"testing"

	"github.com/belotserkovtsev/ladon/internal/config"
	"github.com/belotserkovtsev/ladon/internal/engine"
)

// TestApplyConfigFile_PromoteThresholdAlias pins the backward-compat contract:
// promote_threshold is authoritative, the deprecated fail_threshold is honored
// only as an alias, and promote_threshold wins when both are set. With neither
// set the engine default must survive untouched.
func TestApplyConfigFile_PromoteThresholdAlias(t *testing.T) {
	def := engine.Defaults("x.log").Scorer.PromoteThreshold

	cases := []struct {
		name             string
		promote, failOld int
		want             int
	}{
		{"promote_threshold only", 70, 0, 70},
		{"fail_threshold only (deprecated alias)", 0, 90, 90},
		{"both set — promote_threshold wins", 70, 90, 70},
		{"neither set — engine default kept", 0, 0, def},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := engine.Defaults("x.log")
			f := &config.File{}
			f.Scorer.PromoteThreshold = tc.promote
			f.Scorer.FailThreshold = tc.failOld

			applyConfigFile(&cfg, f)

			if cfg.Scorer.PromoteThreshold != tc.want {
				t.Errorf("PromoteThreshold = %d, want %d", cfg.Scorer.PromoteThreshold, tc.want)
			}
		})
	}
}
