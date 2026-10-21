package golang

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type TestOrder struct {
	ID          string
	OwnerUserID string
	TenantID    string
}

func (o *TestOrder) GetID() string          { return o.ID }
func (o *TestOrder) GetOwnerUserID() string { return o.OwnerUserID }
func (o *TestOrder) GetTenantID() string    { return o.TenantID }

func TestAuthorizer_OwnerAllowed(t *testing.T) {
	sink := &InMemoryAuditSink{}
	auth := NewAuthorizer(sink)

	claims := map[string]interface{}{
		"sub":       "user-a",
		"tenant_id": "tenant-komainu",
	}
	order := &TestOrder{
		ID:          "ord-1",
		OwnerUserID: "user-a",
		TenantID:    "tenant-komainu",
	}

	allowed, reason, err := auth.Authorize(claims, order, OpRead)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected allowed, got false, reason: %s", reason)
	}
	if len(sink.Events) != 0 {
		t.Fatalf("expected 0 audit events, got %d", len(sink.Events))
	}
}

func TestAuthorizer_AttackerDeniedWith404AndAudit(t *testing.T) {
	sink := &InMemoryAuditSink{}
	auth := NewAuthorizer(sink)

	attackerClaims := map[string]interface{}{
		"sub":       "user-b",
		"tenant_id": "tenant-komainu",
	}
	order := &TestOrder{
		ID:          "ord-1",
		OwnerUserID: "user-a",
		TenantID:    "tenant-komainu",
	}

	allowed, reason, _ := auth.Authorize(attackerClaims, order, OpRead)
	if allowed {
		t.Fatalf("expected denied for attacker, got allowed")
	}
	if reason == "" {
		t.Fatalf("expected failure reason")
	}

	// Verify RequireOwnership returns ErrResourceNotFound
	sink.Events = nil // Reset sink
	err := auth.RequireOwnership(attackerClaims, order, OpRead)
	if err != ErrResourceNotFound {
		t.Fatalf("expected ErrResourceNotFound, got: %v", err)
	}

	if len(sink.Events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.Events))
	}
	event := sink.Events[0]
	if event.ActorUserID != "user-b" {
		t.Fatalf("expected actor user-b, got %s", event.ActorUserID)
	}
}

func TestAuthorizer_CrossTenantDenied(t *testing.T) {
	sink := &InMemoryAuditSink{}
	auth := NewAuthorizer(sink)

	crossTenantClaims := map[string]interface{}{
		"sub":       "user-c",
		"tenant_id": "tenant-other",
	}
	order := &TestOrder{
		ID:          "ord-1",
		OwnerUserID: "user-a",
		TenantID:    "tenant-komainu",
	}

	allowed, _, _ := auth.Authorize(crossTenantClaims, order, OpUpdate)
	if allowed {
		t.Fatalf("expected denied for cross-tenant, got allowed")
	}
}

func TestAuthorizer_HTTPMiddleware(t *testing.T) {
	sink := &InMemoryAuditSink{}
	auth := NewAuthorizer(sink)

	orders := map[string]*TestOrder{
		"ord-1": {ID: "ord-1", OwnerUserID: "user-a", TenantID: "tenant-komainu"},
	}

	claimsExtractor := func(r *http.Request) map[string]interface{} {
		token := r.Header.Get("Authorization")
		if token == "Bearer token-user-a" {
			return map[string]interface{}{"sub": "user-a", "tenant_id": "tenant-komainu"}
		}
		if token == "Bearer token-user-b" {
			return map[string]interface{}{"sub": "user-b", "tenant_id": "tenant-komainu"}
		}
		return nil
	}

	loader := func(r *http.Request) (IOwnedResource, error) {
		id := r.URL.Query().Get("id")
		if o, ok := orders[id]; ok {
			return o, nil
		}
		return nil, ErrResourceNotFound
	}

	handler := auth.Middleware(claimsExtractor, loader, OpRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))

	// 1. Owner request -> 200 OK
	reqOwner := httptest.NewRequest("GET", "/order?id=ord-1", nil)
	reqOwner.Header.Set("Authorization", "Bearer token-user-a")
	recOwner := httptest.NewRecorder()
	handler.ServeHTTP(recOwner, reqOwner)
	if recOwner.Code != http.StatusOK {
		t.Fatalf("expected 200 for owner, got %d", recOwner.Code)
	}

	// 2. Attacker request -> 404 Not Found (Invariant)
	reqAttacker := httptest.NewRequest("GET", "/order?id=ord-1", nil)
	reqAttacker.Header.Set("Authorization", "Bearer token-user-b")
	recAttacker := httptest.NewRecorder()
	handler.ServeHTTP(recAttacker, reqAttacker)
	if recAttacker.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for attacker, got %d", recAttacker.Code)
	}
}

func TestAuthorizer_ClaimSemanticsAndEdgeCases(t *testing.T) {
	sink := &InMemoryAuditSink{}
	auth := NewAuthorizer(sink)

	// 1. Supports generic "id" claim and trims whitespace
	claimsWithId := map[string]interface{}{
		"id":        "  user-trimmed  ",
		"tenant_id": " tenant-trimmed ",
	}
	uid, err := auth.GetCurrentUserID(claimsWithId)
	if err != nil || uid != "user-trimmed" {
		t.Fatalf("expected user-trimmed, got %s (err: %v)", uid, err)
	}
	tid, err := auth.GetCurrentTenantID(claimsWithId)
	if err != nil || tid != "tenant-trimmed" {
		t.Fatalf("expected tenant-trimmed, got %s (err: %v)", tid, err)
	}

	// 2. Rejects non-scalar claims (map, slice)
	nonScalarClaims := map[string]interface{}{
		"sub":       map[string]string{"foo": "bar"},
		"tenant_id": []string{"tenant-1"},
	}
	if _, err := auth.GetCurrentUserID(nonScalarClaims); err == nil {
		t.Fatalf("expected error for non-scalar user claim, got nil")
	}
	if _, err := auth.GetCurrentTenantID(nonScalarClaims); err == nil {
		t.Fatalf("expected error for non-scalar tenant claim, got nil")
	}

	// 3. Rejects empty/whitespace owner or tenant on resource
	emptyOwnerOrder := &TestOrder{ID: "ord-1", OwnerUserID: "  ", TenantID: "tenant-komainu"}
	allowed, _, _ := auth.Authorize(claimsWithId, emptyOwnerOrder, OpRead)
	if allowed {
		t.Fatalf("expected denial on resource with empty owner")
	}
}
