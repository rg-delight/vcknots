package profile

import (
	"errors"
	"reflect"
	"testing"

	"github.com/trustknots/vcknots/wallet/common"
)

func TestZeroProfileIsFinal(t *testing.T) {
	if (Profile{}) != Final() {
		t.Fatal("the zero Profile must be Final()")
	}
	if Final().Options() != (Options{}) {
		t.Fatal("Final must carry no option")
	}
}

func TestNames(t *testing.T) {
	tests := []struct {
		profile Profile
		name    string
		draft   bool
	}{
		{Final(), NameFinal, false},
		{HAIP(), NameHAIP, false},
		{Draft13(), NameDraft13, true},
		{Draft24(), NameDraft24, true},
	}
	for _, tt := range tests {
		if got := tt.profile.Name(); got != tt.name {
			t.Errorf("Name() = %q, want %q", got, tt.name)
		}
		if got := tt.profile.String(); got != tt.name {
			t.Errorf("String() = %q, want %q", got, tt.name)
		}
		if got := tt.profile.Draft(); got != tt.draft {
			t.Errorf("%s Draft() = %v, want %v", tt.name, got, tt.draft)
		}
	}
	strengthened, err := Final().With(Options{RequireDPoP: true})
	if err != nil {
		t.Fatal(err)
	}
	if strengthened.Name() != NameFinal || strengthened.String() != "final+options" {
		t.Fatalf("Name/String = %q/%q", strengthened.Name(), strengthened.String())
	}
	if strengthened == Final() {
		t.Fatal("a strengthened Final must not compare equal to Final")
	}
}

// leafFields visits every bool leaf and every set of Options, so a field
// added to Options is covered by the tests below without editing them.
func leafFields(t *testing.T, visit func(path string, field reflect.Value)) {
	t.Helper()
	var walk func(path string, value reflect.Value)
	walk = func(path string, value reflect.Value) {
		switch value.Kind() {
		case reflect.Struct:
			for index := 0; index < value.NumField(); index++ {
				name := value.Type().Field(index).Name
				if path != "" {
					name = path + "." + name
				}
				walk(name, value.Field(index))
			}
		case reflect.Bool, reflect.Uint8, reflect.Uint16:
			visit(path, value)
		default:
			t.Fatalf("Options field %s has unexpected kind %s", path, value.Kind())
		}
	}
	var options Options
	walk("", reflect.ValueOf(&options).Elem())
}

func TestHAIPOptionsTurnsOnEveryRequirement(t *testing.T) {
	haip := reflect.ValueOf(HAIPOptions())
	leafFields(t, func(path string, _ reflect.Value) {
		field := haip.FieldByIndex(fieldIndex(t, path))
		if field.IsZero() {
			t.Errorf("HAIPOptions leaves %s off", path)
		}
	})
	options := HAIPOptions()
	if options.AllowedCredentialFormats != FormatSDJWTVC|FormatMsoMdoc {
		t.Errorf("AllowedCredentialFormats = %s", options.AllowedCredentialFormats)
	}
	if options.AllowedClientIDPrefixes != ClientIDPrefixX509Hash {
		t.Errorf("AllowedClientIDPrefixes = %s", options.AllowedClientIDPrefixes)
	}
	if HAIP().Options() != options {
		t.Fatal("HAIP() must carry HAIPOptions()")
	}
}

func fieldIndex(t *testing.T, path string) []int {
	t.Helper()
	var index []int
	typ := reflect.TypeOf(Options{})
	for _, name := range splitPath(path) {
		field, ok := typ.FieldByName(name)
		if !ok {
			t.Fatalf("no field %s", path)
		}
		index = append(index, field.Index...)
		typ = field.Type
	}
	return index
}

func splitPath(path string) []string {
	var parts []string
	start := 0
	for index := 0; index < len(path); index++ {
		if path[index] == '.' {
			parts = append(parts, path[start:index])
			start = index + 1
		}
	}
	return append(parts, path[start:])
}

func TestWithRefusesWeakeningEveryHAIPOption(t *testing.T) {
	leafFields(t, func(path string, _ reflect.Value) {
		weakened := HAIPOptions()
		field := reflect.ValueOf(&weakened).Elem().FieldByIndex(fieldIndex(t, path))
		field.Set(reflect.Zero(field.Type()))
		_, err := HAIP().With(weakened)
		if !errors.Is(err, ErrProfileMustOption) {
			t.Errorf("HAIP().With without %s: error = %v, want ErrProfileMustOption", path, err)
		}
	})
}

func TestWithRefusesWidenedSets(t *testing.T) {
	widened := HAIPOptions()
	widened.AllowedCredentialFormats |= FormatJWTVCJSON
	if _, err := HAIP().With(widened); !errors.Is(err, ErrProfileMustOption) {
		t.Fatalf("widened formats: error = %v", err)
	}
	widened = HAIPOptions()
	widened.AllowedClientIDPrefixes |= ClientIDPrefixRedirectURI
	if _, err := HAIP().With(widened); !errors.Is(err, ErrProfileMustOption) {
		t.Fatalf("widened prefixes: error = %v", err)
	}
	narrowed := HAIPOptions()
	narrowed.AllowedCredentialFormats = FormatSDJWTVC
	if _, err := HAIP().With(narrowed); err != nil {
		t.Fatalf("narrowed formats: %v", err)
	}
}

func TestMustOptionErrorIsCoded(t *testing.T) {
	_, err := HAIP().With(Options{})
	if code, ok := common.CodeOf(err); !ok || code != "profile_must_option" {
		t.Fatalf("CodeOf = %q, %v", code, ok)
	}
}

func TestWithStrengthensFinal(t *testing.T) {
	partial, err := Final().With(Options{RequireDPoP: true, RequirePAR: true})
	if err != nil {
		t.Fatal(err)
	}
	if !partial.Options().RequireDPoP || !partial.Options().RequirePAR || partial.Options().RequireDirectPostJWT {
		t.Fatalf("options = %+v", partial.Options())
	}
	// Every option the strengthened profile carries is now a floor.
	if _, err := partial.With(Options{RequirePAR: true}); !errors.Is(err, ErrProfileMustOption) {
		t.Fatalf("dropping RequireDPoP: error = %v", err)
	}
	all, err := Final().With(HAIPOptions())
	if err != nil {
		t.Fatal(err)
	}
	if all.Name() != NameFinal || all == HAIP() {
		t.Fatal("Final with every HAIP option stays a Final profile")
	}
	stricter := HAIPOptions()
	stricter.AllowedCredentialFormats = FormatMsoMdoc
	if _, err := HAIP().With(stricter); err != nil {
		t.Fatal(err)
	}
}

func TestDraftProfilesTakeNoOptions(t *testing.T) {
	for _, draft := range []Profile{Draft13(), Draft24()} {
		if _, err := draft.With(Options{RequireDPoP: true}); !errors.Is(err, ErrDraftProfile) {
			t.Errorf("%s.With: error = %v, want ErrDraftProfile", draft.Name(), err)
		}
		if same, err := draft.With(Options{}); err != nil || same != draft {
			t.Errorf("%s.With(zero) = %v, %v", draft.Name(), same, err)
		}
		if err := draft.RequireFinalVersion(); !errors.Is(err, ErrDraftProfile) {
			t.Errorf("%s.RequireFinalVersion = %v", draft.Name(), err)
		}
	}
	if err := HAIP().RequireFinalVersion(); err != nil {
		t.Fatal(err)
	}
}

func TestSets(t *testing.T) {
	var any CredentialFormats
	if !any.Allows("jwt_vc_json") || !any.Allows("unknown") {
		t.Fatal("the empty set allows every format")
	}
	haip := HAIPOptions().AllowedCredentialFormats
	if !haip.Allows("dc+sd-jwt") || !haip.Allows("mso_mdoc") || haip.Allows("jwt_vc_json") || haip.Allows("vc+sd-jwt") {
		t.Fatalf("HAIP formats %s", haip)
	}
	prefixes := HAIPOptions().AllowedClientIDPrefixes
	if !prefixes.Allows("x509_hash") || prefixes.Allows("x509_san_dns") || prefixes.Allows("bogus") {
		t.Fatalf("HAIP prefixes %s", prefixes)
	}
	if (ClientIDPrefixes(0)).String() != "any" || haip.String() != "dc+sd-jwt,mso_mdoc" {
		t.Fatal("String")
	}
}

func TestOptionsCovers(t *testing.T) {
	strict, err := Final().With(HAIPOptions())
	if err != nil {
		t.Fatal(err)
	}
	partial := HAIPOptions()
	partial.RequirePAR = false
	for name, test := range map[string]struct {
		options Options
		want    bool
	}{
		"HAIP":                    {HAIP().Options(), true},
		"Final with HAIP options": {strict.Options(), true},
		"Final":                   {Final().Options(), false},
		"all of HAIP but PAR":     {partial, false},
	} {
		if got := test.options.Covers(HAIPOptions()); got != test.want {
			t.Errorf("%s: Covers(HAIPOptions()) = %v, want %v", name, got, test.want)
		}
	}
	if !Final().Options().Covers(Options{}) {
		t.Error("every Options covers the zero Options")
	}
}
