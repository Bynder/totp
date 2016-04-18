package totp

import "testing"

func TestHOTP(t *testing.T) {
	cases := []struct {
		in   string
		key  int
		want string
	}{
		{"MFRGGZDFMZTWQ2LK", 1, "765705"},
		{"MFRGGZDFMZTWQ2LK", 2, "816065"},
	}
	for _, c := range cases {
		got, err := HOTP(c.in, c.key)
		if err != nil {
			panic(err)
		}
		if got != c.want {
			t.Errorf("HOTP(%q, %q) == %q, want %q", c.in, c.key, got, c.want)
		}
	}
}

func TestTOTP(t *testing.T) {
	cases := []struct {
		in        string
		timestamp int64
		want      string
	}{
		{"MFRGGZDFMZTWQ2LK", 1460984754, "010971"},
		{"MFRGGZDFMZTWQ2LK", 1460984784, "506699"},
	}
	for _, c := range cases {
		got, err := TOTP(c.in, c.timestamp, 30)
		if err != nil {
			panic(err)
		}
		if got != c.want {
			t.Errorf("TOTP(%q, %q, 30) == %q, want %q", c.in, c.timestamp, got, c.want)
		}
	}
}

func TestValidateTOTP(t *testing.T) {
	if !ValidateTOTP("MFRGGZDFMZTWQ2LK", 1460984754, 30, 0, "010971") {
		t.Errorf("Validation on drift 0 failed")
	}
	if !ValidateTOTP("MFRGGZDFMZTWQ2LK", 1460984761, 30, 1, "010971") {
		t.Errorf("Validation on drift 1 failed")
	}
}
