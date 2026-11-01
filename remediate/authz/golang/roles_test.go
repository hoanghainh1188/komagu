package golang

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func withCaller(req *http.Request, id Identity) *http.Request {
	return req.WithContext(WithIdentity(req.Context(), id))
}

var (
	adminCaller  = Identity{UserID: "user-admin", TenantID: "tenant-komagu", Roles: []string{"admin"}}
	regularUser  = Identity{UserID: "user-b", TenantID: "tenant-komagu", Roles: []string{"user"}}
	upperCaseFan = Identity{UserID: "user-c", TenantID: "tenant-komagu", Roles: []string{"Admin"}}
)

func TestRequireRole_Decisions(t *testing.T) {
	cases := []struct {
		name   string
		roles  []string
		opts   []RoleOption
		caller *Identity
		want   int
	}{
		{"allowed with required role", []string{"admin"}, nil, &adminCaller, http.StatusOK},
		{"allowed with any of several roles", []string{"ops", "admin"}, nil, &adminCaller, http.StatusOK},
		{"denied 403 by default", []string{"admin"}, nil, &regularUser, http.StatusForbidden},
		{"denied 404 when hiding endpoint", []string{"admin"}, []RoleOption{WithDenyStatus(http.StatusNotFound)}, &regularUser, http.StatusNotFound},
		{"role match is case-sensitive", []string{"admin"}, nil, &upperCaseFan, http.StatusForbidden},
		{"unauthenticated 401", []string{"admin"}, nil, nil, http.StatusUnauthorized},
		{"blank user id treated as unauthenticated", []string{"admin"}, nil, &Identity{UserID: "  ", Roles: []string{"admin"}}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]RoleOption{WithRoleAuditSink(&InMemoryAuditSink{})}, tc.opts...)
			handler := RequireRole(tc.roles, opts...)(okHandler())
			req := httptest.NewRequest(http.MethodDelete, "/admin/users/42", nil)
			if tc.caller != nil {
				req = withCaller(req, *tc.caller)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, rec.Code)
			}
		})
	}
}

func TestRequireRole_IgnoresRoleClaimsFromRequest(t *testing.T) {
	sink := &InMemoryAuditSink{}
	handler := RequireRole([]string{"admin"}, WithRoleAuditSink(sink))(okHandler())

	body := strings.NewReader(`{"role":"admin","roles":["admin"],"is_admin":true}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/users?role=admin&roles=admin", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Role", "admin")
	req.Header.Set("X-Roles", "admin")
	req = withCaller(req, regularUser)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 despite role=admin in query, body and X-Role header, got %d", rec.Code)
	}
	if len(sink.Events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.Events))
	}
}

func TestRequireRole_EmitsAuditEventOnDenial(t *testing.T) {
	sink := &InMemoryAuditSink{}
	auth := NewAuthorizer(sink)
	handler := auth.RequireRole([]string{"admin", "ops"})(okHandler())

	req := withCaller(httptest.NewRequest(http.MethodDelete, "/admin/users/42", nil), regularUser)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if len(sink.Events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.Events))
	}
	ev := sink.Events[0]
	if ev.EventName != "Komagu.Authorization.RoleDenied" {
		t.Fatalf("unexpected event name %q", ev.EventName)
	}
	if ev.ActorUserID != "user-b" || ev.ActorTenantID != "tenant-komagu" {
		t.Fatalf("unexpected actor %q/%q", ev.ActorUserID, ev.ActorTenantID)
	}
	if !strings.Contains(ev.Reason, "admin") || !strings.Contains(ev.Reason, "ops") {
		t.Fatalf("reason should name required roles, got %q", ev.Reason)
	}
	if ev.Operation != ResourceOperation(http.MethodDelete) || ev.ResourceID != "/admin/users/42" {
		t.Fatalf("unexpected operation/resource %q %q", ev.Operation, ev.ResourceID)
	}
	if ev.Timestamp.IsZero() {
		t.Fatalf("expected timestamp")
	}
}

func TestRequireRole_NoAuditOnAllowOrUnauthenticated(t *testing.T) {
	sink := &InMemoryAuditSink{}
	handler := RequireRole([]string{"admin"}, WithRoleAuditSink(sink))(okHandler())

	handler.ServeHTTP(httptest.NewRecorder(), withCaller(httptest.NewRequest(http.MethodGet, "/admin", nil), adminCaller))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin", nil))
	if len(sink.Events) != 0 {
		t.Fatalf("expected 0 audit events, got %d", len(sink.Events))
	}
}

func TestRequireRole_InvalidConfigurationPanics(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
		opts  []RoleOption
	}{
		{"nil roles", nil, nil},
		{"empty roles", []string{}, nil},
		{"blank role", []string{"admin", " "}, nil},
		{"deny status 401", []string{"admin"}, []RoleOption{WithDenyStatus(http.StatusUnauthorized)}},
		{"deny status 200", []string{"admin"}, []RoleOption{WithDenyStatus(http.StatusOK)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected panic")
				}
			}()
			RequireRole(tc.roles, tc.opts...)
		})
	}
}

func TestIdentity_ContextCopiesRoles(t *testing.T) {
	roles := []string{"user"}
	req := withCaller(httptest.NewRequest(http.MethodGet, "/", nil), Identity{UserID: "u1", Roles: roles})
	roles[0] = "admin" // caller mutates its slice after storing

	got, ok := IdentityFromContext(req.Context())
	if !ok || got.HasAnyRole("admin") {
		t.Fatalf("stored identity must not change when the original slice is mutated: %+v", got)
	}
	got.Roles[0] = "admin" // reader mutates the returned copy
	again, _ := IdentityFromContext(req.Context())
	if again.HasAnyRole("admin") {
		t.Fatalf("returned identity must be a copy")
	}
}
