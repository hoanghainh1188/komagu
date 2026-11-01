package golang

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestAllowFields(t *testing.T) {
	cases := []struct {
		name    string
		src     map[string]any
		allowed []string
		want    map[string]any
	}{
		{
			name:    "picks allowed keys only",
			src:     map[string]any{"name": "Ann", "email": "a@x.io", "role": "admin", "is_admin": true},
			allowed: []string{"name", "email"},
			want:    map[string]any{"name": "Ann", "email": "a@x.io"},
		},
		{
			name:    "skips allowed keys missing from src",
			src:     map[string]any{"name": "Ann"},
			allowed: []string{"name", "email"},
			want:    map[string]any{"name": "Ann"},
		},
		{
			name:    "keys are case-sensitive",
			src:     map[string]any{"Name": "Ann"},
			allowed: []string{"name"},
			want:    map[string]any{},
		},
		{name: "nil src returns empty map", src: nil, allowed: []string{"name"}, want: map[string]any{}},
		{name: "no allowed keys returns empty map", src: map[string]any{"name": "Ann"}, want: map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AllowFields(tc.src, tc.allowed...)
			if got == nil {
				t.Fatalf("expected non-nil map")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestAllowFields_DoesNotMutateSource(t *testing.T) {
	src := map[string]any{"name": "Ann", "role": "admin"}
	out := AllowFields(src, "name")
	out["name"] = "changed"
	out["extra"] = 1

	want := map[string]any{"name": "Ann", "role": "admin"}
	if !reflect.DeepEqual(src, want) {
		t.Fatalf("src was mutated: %v", src)
	}
}

// --- DTO allow-list example -------------------------------------------------

// User is the domain model; Role and IsAdmin must never be set from client input.
type User struct {
	ID      string
	Name    string
	Email   string
	Role    string
	IsAdmin bool
}

// ProfileUpdate is the narrow request DTO: only the fields a user may change.
type ProfileUpdate struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// decodeProfileUpdate rejects any field outside the DTO (strict mode).
func decodeProfileUpdate(body string) (ProfileUpdate, error) {
	var dto ProfileUpdate
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&dto); err != nil {
		return ProfileUpdate{}, err
	}
	return dto, nil
}

// applyProfileUpdate copies DTO fields explicitly and returns a new User.
func applyProfileUpdate(u User, dto ProfileUpdate) User {
	u.Name = dto.Name
	u.Email = dto.Email
	return u
}

func TestDTOAllowList_StrictDecodeRejectsPrivilegedFields(t *testing.T) {
	for _, body := range []string{
		`{"name":"Ann","role":"admin"}`,
		`{"name":"Ann","is_admin":true}`,
		`{"name":"Ann","IsAdmin":true}`,
	} {
		if _, err := decodeProfileUpdate(body); err == nil {
			t.Fatalf("expected strict decode to reject %s", body)
		}
	}
}

func TestDTOAllowList_ExplicitCopyCannotEscalate(t *testing.T) {
	current := User{ID: "u1", Name: "Old", Email: "old@x.io", Role: "user", IsAdmin: false}
	body := `{"name":"Ann","email":"ann@x.io","role":"admin","is_admin":true}`

	// Lenient decode into the narrow DTO: unknown fields are dropped, not applied.
	var dto ProfileUpdate
	if err := json.Unmarshal([]byte(body), &dto); err != nil {
		t.Fatalf("decode: %v", err)
	}
	updated := applyProfileUpdate(current, dto)

	if updated.Role != "user" || updated.IsAdmin {
		t.Fatalf("privileged fields reached the domain model: %+v", updated)
	}
	if updated.Name != "Ann" || updated.Email != "ann@x.io" {
		t.Fatalf("allowed fields not applied: %+v", updated)
	}
	if current.Name != "Old" {
		t.Fatalf("original user was mutated: %+v", current)
	}

	// Strict decode of the same body fails outright.
	if _, err := decodeProfileUpdate(body); err == nil {
		t.Fatalf("expected strict decode to reject privileged fields")
	}
}
