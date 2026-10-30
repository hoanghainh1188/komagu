# Komainu Object-Level Authorization Library (D1)

The **Komainu Object-Level Authorization Library** is the core application-layer defense against **Broken Object Level Authorization (BOLA)** and **Insecure Direct Object Reference (IDOR)** (OWASP API Security Top 10 API1:2023 / CWE-639 / CWE-284).

It provides standardized, high-performance security primitives for both **.NET 8 (ASP.NET Core & EF Core)** and **Spring Boot 3 (Kotlin & Java / Spring Data JPA)**.

---

## 1. Core Security Invariants

All implementations strictly enforce these architectural guarantees:

1. **Identity Strictly from Verified Token Claims:** User subject (`sub`, `uid`) and organization tenant (`tenant_id`, `tid`) are extracted exclusively from cryptographically verified token claims in the security context. No identity binding from path parameters, query strings, or request bodies is permitted.
2. **Deny-by-Default with HTTP 404 Not Found:** When an authenticated user requests a resource that exists but belongs to a different user or tenant, the library **returns HTTP 404 Not Found** instead of `403 Forbidden`. This eliminates ID enumeration and prevents attackers from probing the existence of internal IDs.
3. **Dual API Styles:**
   - **Imperative (Programmatic):** Explicit service calls (`AuthorizeAsync` / `requireOwnership`) for complex business workflows and multi-condition rules.
   - **Declarative (Metadata/Attribute/Annotation):** Endpoint filter (`[RequireOwnership]`) or AOP Aspect (`@RequireOwnership`) for clean, declarative controller boundaries.
4. **Scoped Data-Access Helpers:** Query pipeline extensions (EF Core `WithUserScope`, Spring Data `ScopedRepository`) automatically appending tenant and owner constraints to SQL queries before execution.
5. **Structured Security Audit Logging:** Every denial emits a structured event (`Komainu.Authorization.Denied`) with `actorUserId`, `actorTenantId`, `resourceType`, `resourceId`, and failure rationale for SIEM and security monitoring.

---

## 2. .NET 8 (C#) Usage

### Installation & Registration

In your ASP.NET Core `Program.cs`:

```csharp
using Komainu.Security.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Register authentication (JWT / OIDC)
builder.Services.AddAuthentication(...);

// Register Komainu Authorization services
builder.Services.AddKomainuAuthorization();

var app = builder.Build();
```

### Implementing `IOwnedResource` on Domain Entities

```csharp
using Komainu.Security.Authorization;

public class Order : IOwnedResource<Guid>, IOwnedResource
{
    public Guid Id { get; set; }
    public string OwnerUserId { get; set; } = string.Empty;
    public string TenantId { get; set; } = string.Empty;
    public decimal TotalAmount { get; set; }
}
```

### Imperative Style

```csharp
[HttpGet("{id:guid}")]
public async Task<IActionResult> GetOrder(
    Guid id,
    [FromServices] IKomainuAuthorizationService authService,
    [FromServices] MyDbContext dbContext)
{
    var order = await dbContext.Orders.FindAsync(id);
    if (order == null) return NotFound();

    var authResult = await authService.AuthorizeAsync(User, order, ResourceOperation.Read);
    if (!authResult.Succeeded)
    {
        // Automatically returns 404 Not Found to prevent ID enumeration
        return NotFound();
    }

    return Ok(order);
}
```

### Declarative Style (Action Filter)

```csharp
[HttpGet("{id:guid}")]
[RequireOwnership(typeof(Order), idRouteParameter: "id", operation: ResourceOperation.Read)]
public async Task<IActionResult> GetOrderDeclarative(Guid id)
{
    // If execution reaches here, ownership has been verified
    ...
}
```

### Scoped EF Core Queries

```csharp
using Komainu.Security.EntityFrameworkCore;

var currentUserId = authService.GetCurrentUserId(User);
var currentTenantId = authService.GetCurrentTenantId(User);

// Appends "WHERE tenant_id = @tenantId AND owner_user_id = @userId" to SQL
var myOrders = await dbContext.Orders
    .WithUserScope<Order, Guid>(currentUserId, currentTenantId)
    .ToListAsync();
```

---

## 3. Spring Boot 3 (Kotlin / Java) Usage

### Domain Entity

```kotlin
import io.komagu.security.authorization.OwnedResource
import java.util.UUID

data class Order(
    override val id: UUID,
    override val ownerUserId: String,
    override val tenantId: String,
    val totalAmount: Double
) : OwnedResource<UUID>
```

### Imperative Style

```kotlin
@RestController
@RequestMapping("/api/v1/orders")
class OrderController(
    private val securityManager: KomaguSecurityManager,
    private val orderRepository: OrderRepository
) {
    @GetMapping("/{id}")
    fun getOrder(@PathVariable id: UUID): Order {
        val order = orderRepository.findById(id).orElseThrow { ResourceNotFoundException() }
        
        // Throws ResourceNotFoundException (HTTP 404) if owner or tenant mismatches
        securityManager.requireOwnership(order, ResourceOperation.READ)
        
        return order
    }
}
```

### Declarative Style (Annotation & Aspect)

```kotlin
@GetMapping("/{id}")
@RequireOwnership(entityClass = Order::class, operation = ResourceOperation.READ)
fun getOrder(@PathVariable id: UUID): Order {
    return orderRepository.findById(id).orElseThrow { ResourceNotFoundException() }
}
```

### Scoped Repository Access (Spring Data JPA)

```kotlin
import io.komagu.security.data.ScopedRepository
import java.util.UUID

interface OrderRepository : ScopedRepository<Order, UUID> {
    // Inherits findByIdAndTenantIdAndOwnerUserId and findAllByTenantIdAndOwnerUserId
}
```

---

## 4. Python (FastAPI) Usage

### Domain Entity & Injections

```python
from dataclasses import dataclass
from fastapi import FastAPI, Depends
from remediate.authz.python.komainu_authz import (
    KomainuAuthorizationService,
    RequireOwnership,
    ResourceOperation,
    get_current_user,
    UserPrincipal,
    IOwnedResource,
)

@dataclass
class Order(IOwnedResource):
    id: str
    owner_user_id: str
    tenant_id: str
    description: str

app = FastAPI()

def get_order_by_id(order_id: str) -> Order:
    return db.find_order(order_id)

@app.get("/api/v1/orders/{order_id}")
def read_order(
    order: Order = Depends(
        RequireOwnership(
            operation=ResourceOperation.READ,
            id_param="order_id",
            loader=get_order_by_id,
        )
    )
):
    return order
```

---

## 5. Node.js (NestJS & Express) Usage

### NestJS Declarative Guard & Interceptor

```typescript
import { Controller, Get, Param, UseGuards, UseInterceptors } from '@nestjs/common';
import {
  RequireOwnership,
  OwnershipGuard,
  OwnershipInterceptor,
  ResourceOperation,
} from '@komainu/security-authz';

@Controller('api/v1/orders')
@UseGuards(OwnershipGuard)
@UseInterceptors(OwnershipInterceptor)
export class OrderController {
  constructor(private readonly orderService: OrderService) {}

  @Get(':id')
  @RequireOwnership(ResourceOperation.READ, {
    idParamName: 'id',
    resourceLoader: (id, req) => orderService.findById(id),
  })
  async getOrder(@Param('id') id: string) {
    return this.orderService.findById(id);
  }
}
```

### Express.js Middleware

```javascript
const { komainuOwnershipMiddleware, ResourceOperation } = require('@komainu/security-authz');

app.get('/api/v1/orders/:id',
  komainuOwnershipMiddleware({
    operation: ResourceOperation.READ,
    idParamName: 'id',
    resourceLoader: async (id, req) => db.orders.findById(id),
  }),
  (req, res) => {
    res.json(req.komainuResource);
  }
);
```

---

## 6. Go Usage

```go
import (
    "net/http"
    authz "github.com/hoanghainh1188/komainu/remediate/authz/golang"
)

func RegisterOrderRoutes(mux *http.ServeMux, authorizer *authz.Authorizer) {
    mux.Handle("/api/v1/orders", authorizer.Middleware(
        extractClaims,
        loadOrder,
        authz.OpRead,
    )(http.HandlerFunc(handleGetOrder)))
}
```

---

## 7. Test Verification & D5 Runner

All multi-language adapters verify identical BOLA defense invariants:

- **.NET 8:**
  ```bash
  dotnet test remediate/authz/dotnet/Komainu.Security.Authz.slnx
  ```
- **Spring Boot 3:**
  ```bash
  gradle -p remediate/authz/spring test
  ```
- **Python (FastAPI & D5 Runner):**
  ```bash
  python3 -m unittest discover -s remediate/authz/python/tests -p "test_*.py"
  ```
- **Node.js (NestJS & Express):**
  ```bash
  node --test remediate/authz/nodejs/tests/test-authz.js
  ```
- **Go:**
  ```bash
  go test -v remediate/authz/golang/...
  ```

