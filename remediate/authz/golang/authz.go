// Package golang provides Komagu Object-Level Authorization (D1) for Go.
//
// Strictly enforces tenant and user ownership boundaries (BOLA defense).
// Denies access with HTTP 404 (ErrResourceNotFound) to prevent ID enumeration.
package golang

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// ResourceOperation defines the CRUD operation on a protected resource.
type ResourceOperation string

const (
	OpRead   ResourceOperation = "Read"
	OpCreate ResourceOperation = "Create"
	OpUpdate ResourceOperation = "Update"
	OpDelete ResourceOperation = "Delete"
)

// ErrResourceNotFound is returned on authorization failure to prevent ID enumeration.
var ErrResourceNotFound = errors.New("resource not found")

// ErrUnauthorized is returned when caller identity claims are missing.
var ErrUnauthorized = errors.New("unauthorized caller")

// IOwnedResource represents domain resources with user and tenant ownership.
type IOwnedResource interface {
	GetID() string
	GetOwnerUserID() string
	GetTenantID() string
}

// SecurityAuditEvent records authorization denials for audit trails and SIEM.
type SecurityAuditEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	EventName     string            `json:"event_name"`
	ActorUserID   string            `json:"actor_user_id,omitempty"`
	ActorTenantID string            `json:"actor_tenant_id,omitempty"`
	ResourceType  string            `json:"resource_type"`
	ResourceID    string            `json:"resource_id,omitempty"`
	Operation     ResourceOperation `json:"operation"`
	Reason        string            `json:"reason"`
}

// AuditSink publishes security audit events.
type AuditSink interface {
	Emit(event SecurityAuditEvent)
}

// LoggingAuditSink outputs events to standard logger.
type LoggingAuditSink struct{}

func (s *LoggingAuditSink) Emit(event SecurityAuditEvent) {
	data, _ := json.Marshal(event)
	log.Printf("SECURITY_AUDIT: %s", string(data))
}

// InMemoryAuditSink stores events for test verification.
type InMemoryAuditSink struct {
	Events []SecurityAuditEvent
}

func (s *InMemoryAuditSink) Emit(event SecurityAuditEvent) {
	s.Events = append(s.Events, event)
}

// Authorizer enforces object-level authorization in Go applications.
type Authorizer struct {
	Sink AuditSink
}

// NewAuthorizer creates a new Komagu Authorizer.
func NewAuthorizer(sink AuditSink) *Authorizer {
	if sink == nil {
		sink = &LoggingAuditSink{}
	}
	return &Authorizer{Sink: sink}
}

var (
	userIdClaims   = []string{"sub", "uid", "userId", "user_id", "id"}
	tenantIdClaims = []string{"tenant_id", "tid", "tenant", "org_id", "organization_id"}
)

func extractScalarClaim(val interface{}) (string, bool) {
	if val == nil {
		return "", false
	}
	switch v := val.(type) {
	case string:
		str := strings.TrimSpace(v)
		return str, str != ""
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v), true
	case float32, float64:
		// JSON numbers unmarshal as float64
		str := strings.TrimSpace(fmt.Sprintf("%.0f", v))
		return str, str != ""
	default:
		// Non-scalar claims (slices, maps, structs, bools) are rejected
		return "", false
	}
}

// GetCurrentUserID extracts verified user subject identifier from claims.
func (a *Authorizer) GetCurrentUserID(claims map[string]interface{}) (string, error) {
	if claims == nil {
		return "", ErrUnauthorized
	}
	for _, k := range userIdClaims {
		if val, ok := claims[k]; ok {
			if str, ok := extractScalarClaim(val); ok {
				return str, nil
			}
		}
	}
	return "", errors.New("verified user subject claim is missing")
}

// GetCurrentTenantID extracts verified tenant identifier from claims.
func (a *Authorizer) GetCurrentTenantID(claims map[string]interface{}) (string, error) {
	if claims == nil {
		return "", ErrUnauthorized
	}
	for _, k := range tenantIdClaims {
		if val, ok := claims[k]; ok {
			if str, ok := extractScalarClaim(val); ok {
				return str, nil
			}
		}
	}
	return "", errors.New("verified tenant identifier claim is missing")
}

// Authorize evaluates whether claims allow the given operation on resource.
func (a *Authorizer) Authorize(claims map[string]interface{}, resource IOwnedResource, op ResourceOperation) (bool, string, error) {
	if claims == nil {
		reason := "Caller is unauthenticated"
		a.emitDenial("", "", resource, op, reason)
		return false, reason, nil
	}

	userId, err := a.GetCurrentUserID(claims)
	if err != nil {
		a.emitDenial("", "", resource, op, err.Error())
		return false, err.Error(), nil
	}

	tenantId, err := a.GetCurrentTenantID(claims)
	if err != nil {
		a.emitDenial(userId, "", resource, op, err.Error())
		return false, err.Error(), nil
	}

	if resource == nil {
		return false, "Resource is nil", nil
	}

	resOwner := strings.TrimSpace(resource.GetOwnerUserID())
	resTenant := strings.TrimSpace(resource.GetTenantID())

	if resOwner == "" || resTenant == "" {
		reason := "Target resource does not expose valid owner and tenant"
		a.emitDenial(userId, tenantId, resource, op, reason)
		return false, reason, nil
	}

	// 1. Tenant boundary enforcement
	if resTenant != tenantId {
		reason := fmt.Sprintf("Tenant boundary violation: current tenant '%s' != resource tenant '%s'", tenantId, resTenant)
		a.emitDenial(userId, tenantId, resource, op, reason)
		return false, reason, nil
	}

	// 2. User ownership enforcement
	if resOwner != userId {
		reason := fmt.Sprintf("User ownership violation: current user '%s' != resource owner '%s'", userId, resOwner)
		a.emitDenial(userId, tenantId, resource, op, reason)
		return false, reason, nil
	}

	return true, "", nil
}

// RequireOwnership checks ownership and returns ErrResourceNotFound on denial (BOLA protection).
func (a *Authorizer) RequireOwnership(claims map[string]interface{}, resource IOwnedResource, op ResourceOperation) error {
	allowed, _, _ := a.Authorize(claims, resource, op)
	if !allowed {
		return ErrResourceNotFound
	}
	return nil
}

func (a *Authorizer) emitDenial(userId, tenantId string, resource IOwnedResource, op ResourceOperation, reason string) {
	var resId, resType string
	if resource != nil {
		resId = resource.GetID()
		resType = fmt.Sprintf("%T", resource)
	} else {
		resType = "Unknown"
	}

	a.Sink.Emit(SecurityAuditEvent{
		Timestamp:     time.Now().UTC(),
		EventName:     "Komagu.Authorization.Denied",
		ActorUserID:   userId,
		ActorTenantID: tenantId,
		ResourceType:  resType,
		ResourceID:    resId,
		Operation:     op,
		Reason:        reason,
	})
}

// ContextKey for attaching verified resource to request context.
type contextKey string

const ResourceContextKey contextKey = "komaguResource"

// Middleware creates standard net/http middleware enforcing object ownership.
func (a *Authorizer) Middleware(
	claimsExtractor func(r *http.Request) map[string]interface{},
	resourceLoader func(r *http.Request) (IOwnedResource, error),
	op ResourceOperation,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := claimsExtractor(r)
			if claims == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			res, err := resourceLoader(r)
			if err != nil || res == nil {
				http.Error(w, `{"error":"resource not found"}`, http.StatusNotFound)
				return
			}

			if err := a.RequireOwnership(claims, res, op); err != nil {
				// Core Invariant: Return 404 Not Found on BOLA failure
				http.Error(w, `{"error":"resource not found"}`, http.StatusNotFound)
				return
			}

			ctx := context.WithValue(r.Context(), ResourceContextKey, res)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
