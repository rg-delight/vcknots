package profile

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name    string
		in      Profile
		want    Profile
		wantErr bool
	}{
		{name: "zero is Final", in: "", want: Final},
		{name: "explicit final", in: Final, want: Final},
		{name: "haip", in: "haip", want: HAIP},
		{name: "uppercase HAIP is unknown", in: "HAIP", wantErr: true},
		{name: "draft24 is unknown", in: "draft24", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.Normalize()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Normalize(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Fatalf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsHAIP(t *testing.T) {
	if Final.IsHAIP() || Profile("").IsHAIP() || Profile("draft24").IsHAIP() {
		t.Fatal("only HAIP must report IsHAIP")
	}
	if !HAIP.IsHAIP() {
		t.Fatal("HAIP must report IsHAIP")
	}
}
