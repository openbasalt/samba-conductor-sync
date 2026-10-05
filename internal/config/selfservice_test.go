package config

import (
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-sync/syncapi"
)

func withSelfService(s syncapi.Settings, activation string, minLen int) syncapi.Settings {
	s.SelfService = &syncapi.SelfServiceSettings{Activation: activation, PasswordMinLength: minLen}
	return s
}

func TestSelfServicePolicy(t *testing.T) {
	c, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if e := c.SelfService.Effective(); e != SelfServiceDefaults || c.PlanPolicy().SelfServiceActivation {
		t.Fatalf("defaults %+v", e)
	}
	// Defaults travel as nil (older clients keep decoding).
	if s := SettingsOf(c); s.SelfService != nil {
		t.Fatalf("defaults sent: %+v", s.SelfService)
	}
	_, err = Load(write(t, minimal+"[self_service]\nactivation = \"later\"\npassword_reset = \"all\"\nchosen_password = \"yes\"\npassword_min_length = 6\nmax_per_user_hour = -1\n"))
	for _, want := range []string{"self_service.activation", "self_service.password_reset", "self_service.chosen_password",
		"self_service.password_min_length", "self_service.max_per_user_hour"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	c, err = Load(write(t, minimal+"[self_service]\nactivation = \"self-service\"\npassword_reset = \"created-and-adopted\"\nchosen_password = \"allow\"\npassword_min_length = 16\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.PlanPolicy().SelfServiceActivation {
		t.Fatal("activation not in the plan policy")
	}
	s := SettingsOf(c)
	if s.SelfService == nil || s.SelfService.Activation != "self-service" || s.SelfService.PasswordReset != "created-and-adopted" ||
		s.SelfService.ChosenPassword != "allow" || s.SelfService.PasswordMinLength != 16 || s.SelfService.MaxPerUserHour != 0 {
		t.Fatalf("settings %+v", s.SelfService)
	}
	// nil (a client that does not know the field) keeps the file's values.
	s.SelfService = nil
	n, err := c.Overlay(s, 2)
	if err != nil || n.SelfService.Effective().Activation != "self-service" || n.SelfService.Effective().PasswordMinLength != 16 {
		t.Fatalf("overlay nil: %v %+v", err, n.SelfService)
	}
	// An explicit value replaces it; an empty one keeps the file's.
	n, err = c.Overlay(withSelfService(s, "auto", 20), 3)
	if err != nil || n.SelfService.Effective().Activation != "auto" || n.SelfService.Effective().PasswordReset != "created-and-adopted" ||
		n.SelfService.Effective().PasswordMinLength != 20 || n.PlanPolicy().SelfServiceActivation {
		t.Fatalf("overlay value: %v %+v", err, n.SelfService)
	}
	if _, err := c.Overlay(withSelfService(s, "sometimes", 0), 4); err == nil || !strings.Contains(err.Error(), "self_service.activation") {
		t.Fatalf("bad overlay value accepted: %v", err)
	}
}
