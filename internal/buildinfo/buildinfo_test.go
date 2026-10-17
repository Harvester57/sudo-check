package buildinfo

import "testing"

func TestSet(t *testing.T) {
	origV, origC, origD := Version, Commit, Date
	defer func() {
		Version, Commit, Date = origV, origC, origD
	}()

	Set("v2.0.0", "abc1234", "2026-10-17")
	if Version != "v2.0.0" {
		t.Errorf("expected Version v2.0.0, got %s", Version)
	}
	if Commit != "abc1234" {
		t.Errorf("expected Commit abc1234, got %s", Commit)
	}
	if Date != "2026-10-17" {
		t.Errorf("expected Date 2026-10-17, got %s", Date)
	}
}
