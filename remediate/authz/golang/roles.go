package golang

// Komagu Function-Level Authorization (BFLA defense) for Go.
//
// RequireRole guards an http.Handler so that only callers holding at least
// one of the required roles reach it. Caller identity and roles are read
// ONLY from the trusted Identity that the authentication layer placed in
// the request context via WithIdentity. Roles are never read from the
// request body, query string, path or headers.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RoleDeniedEventName is the audit event name emitted when RequireRole denies a caller.
const RoleDeniedEventName = "Komagu.Authorization.RoleDenied"

// Identity is the verified caller identity produced by authentication.
type Identity struct {
	UserID   string
	TenantID string
	Roles    []string
}

// HasAnyRole reports whether the identity holds at least one of roles.
// Matching is exact and case-sensitive.
func (id Identity) HasAnyRole(roles ...string) bool {
	for _, held := range id.Roles {
		for _, want := range roles {
			if held == want {
				return true
			}
		}
	}
	return false
}

const identityContextKey contextKey = "komaguIdentity"

// WithIdentity returns a copy of ctx carrying id. Call it from authentication
// middleware after the token or session has been verified. The Roles slice is
// copied so later changes by the caller do not affect the stored identity.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	stored := Identity{
		UserID:   id.UserID,
		TenantID: id.TenantID,
		Roles:    append([]string(nil), id.Roles...),
	}
	return context.WithValue(ctx, identityContextKey, stored)
}

// IdentityFromContext returns the identity stored by WithIdentity. The second
// result is false when no identity is present or its UserID is blank.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityContextKey).(Identity)
	if !ok || strings.TrimSpace(id.UserID) == "" {
		return Identity{}, false
	}
	id.Roles = append([]string(nil), id.Roles...)
	return id, true
}

type roleConfig struct {
	denyStatus int
	sink       AuditSink
}

// RoleOption configures RequireRole.
type RoleOption func(*roleConfig)

// WithDenyStatus sets the status returned when the caller lacks the role.
// Only http.StatusForbidden (default) and http.StatusNotFound (hides the
// endpoint) are accepted; any other value makes RequireRole panic.
func WithDenyStatus(status int) RoleOption {
	return func(c *roleConfig) { c.denyStatus = status }
}

// WithRoleAuditSink sets the sink that receives RoleDenied events.
// A nil sink falls back to LoggingAuditSink.
func WithRoleAuditSink(sink AuditSink) RoleOption {
	return func(c *roleConfig) { c.sink = sink }
}

// RequireRole returns net/http middleware that allows the request only when
// the context Identity holds at least one of roles (exact, case-sensitive).
//
//   - no Identity in context -> 401 {"error":"unauthorized"}
//   - Identity without a required role -> 403 {"error":"forbidden"}, or
//     404 {"error":"resource not found"} with WithDenyStatus(http.StatusNotFound),
//     and a RoleDeniedEventName audit event.
//
// RequireRole panics at construction (route registration) when roles is
// empty, contains a blank role, or WithDenyStatus is not 403 or 404.
func RequireRole(roles []string, opts ...RoleOption) func(http.Handler) http.Handler {
	required := validateRoles(roles)
	cfg := roleConfig{denyStatus: http.StatusForbidden}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.denyStatus != http.StatusForbidden && cfg.denyStatus != http.StatusNotFound {
		panic(fmt.Sprintf("komagu: RequireRole deny status must be 403 or 404, got %d", cfg.denyStatus))
	}
	if cfg.sink == nil {
		cfg.sink = &LoggingAuditSink{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := IdentityFromContext(r.Context())
			if !ok {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if !id.HasAnyRole(required...) {
				emitRoleDenial(cfg.sink, id, r, required)
				writeRoleDenial(w, cfg.denyStatus)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole is RequireRole using the Authorizer's audit sink. An explicit
// WithRoleAuditSink option still takes precedence.
func (a *Authorizer) RequireRole(roles []string, opts ...RoleOption) func(http.Handler) http.Handler {
	all := append([]RoleOption{WithRoleAuditSink(a.Sink)}, opts...)
	return RequireRole(roles, all...)
}

func validateRoles(roles []string) []string {
	if len(roles) == 0 {
		panic("komagu: RequireRole needs at least one role")
	}
	for _, role := range roles {
		if strings.TrimSpace(role) == "" {
			panic("komagu: RequireRole roles must not be blank")
		}
	}
	return append([]string(nil), roles...)
}

func writeRoleDenial(w http.ResponseWriter, status int) {
	if status == http.StatusNotFound {
		http.Error(w, `{"error":"resource not found"}`, http.StatusNotFound)
		return
	}
	http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
}

func emitRoleDenial(sink AuditSink, id Identity, r *http.Request, required []string) {
	sink.Emit(SecurityAuditEvent{
		Timestamp:     time.Now().UTC(),
		EventName:     RoleDeniedEventName,
		ActorUserID:   id.UserID,
		ActorTenantID: id.TenantID,
		ResourceType:  "HTTPEndpoint",
		ResourceID:    r.URL.Path,
		Operation:     ResourceOperation(r.Method),
		Reason:        fmt.Sprintf("Caller lacks required role; requires any of [%s]", strings.Join(required, ", ")),
	})
}
