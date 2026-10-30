namespace MemberPortal.Backend.Controllers;

using MemberPortal.Backend.Data;
using MemberPortal.Backend.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Komagu.Security.Authorization;
using Komagu.Security.EntityFrameworkCore;
using Komagu.Security.Query;

[ApiController]
[Route("api/v1/orders")]
public class OrdersController : ControllerBase
{
    private readonly PortalDbContext _dbContext;
    private readonly IKomaguAuthorizationService _authzService;

    private static readonly SafeSortAllowList SortAllowList = new(
        new[] { "CreatedAt", "TotalAmount", "Status", "Id" }
    );

    public OrdersController(PortalDbContext dbContext, IKomaguAuthorizationService authzService)
    {
        _dbContext = dbContext;
        _authzService = authzService;
    }

    [HttpGet]
    public async Task<ActionResult<List<Order>>> ListOrders([FromQuery] string? sort = null, [FromQuery] string? dir = "desc")
    {
        var userId = _authzService.GetCurrentUserId(User);
        var tenantId = _authzService.GetCurrentTenantId(User);

        // Apply D1 tenant & user scoped filtering at the database layer
        IQueryable<Order> query = _dbContext.Orders.WithUserScope<Order, string>(userId, tenantId);

        if (!string.IsNullOrWhiteSpace(sort))
        {
            var validCol = SortAllowList.ValidateColumnName(sort);
            var isAsc = string.Equals(dir, "asc", StringComparison.OrdinalIgnoreCase);

            query = validCol.ToLowerInvariant() switch
            {
                "totalamount" => isAsc ? query.OrderBy(o => o.TotalAmount) : query.OrderByDescending(o => o.TotalAmount),
                "status" => isAsc ? query.OrderBy(o => o.Status) : query.OrderByDescending(o => o.Status),
                _ => isAsc ? query.OrderBy(o => o.CreatedAt) : query.OrderByDescending(o => o.CreatedAt)
            };
        }
        else
        {
            query = query.OrderByDescending(o => o.CreatedAt);
        }

        var orders = await query.ToListAsync();
        return Ok(orders);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Order>> GetOrder(string id)
    {
        var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
        if (order == null)
        {
            return NotFound(new { error = "Order not found" });
        }

        // Enforce object-level ownership check (D1 invariant)
        var authResult = await _authzService.AuthorizeAsync(User, order, ResourceOperation.Read);
        if (!authResult.Succeeded)
        {
            // Always return 404 Not Found to prevent oracle ID probing
            return NotFound(new { error = "Order not found" });
        }

        return Ok(order);
    }

    [HttpPost]
    public async Task<ActionResult<Order>> CreateOrder([FromBody] CreateOrderRequest request)
    {
        var userId = _authzService.GetCurrentUserId(User);
        var tenantId = _authzService.GetCurrentTenantId(User);

        var order = new Order
        {
            TenantId = tenantId,
            OwnerUserId = userId,
            TotalAmount = request.TotalAmount,
            Description = request.Description,
            Status = "pending",
            CreatedAt = DateTime.UtcNow
        };

        _dbContext.Orders.Add(order);
        await _dbContext.SaveChangesAsync();

        return CreatedAtAction(nameof(GetOrder), new { id = order.Id }, order);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<Order>> UpdateOrder(string id, [FromBody] UpdateOrderRequest request)
    {
        var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
        if (order == null)
        {
            return NotFound(new { error = "Order not found" });
        }

        var authResult = await _authzService.AuthorizeAsync(User, order, ResourceOperation.Update);
        if (!authResult.Succeeded)
        {
            return NotFound(new { error = "Order not found" });
        }

        order.Description = request.Description ?? order.Description;
        order.Status = request.Status ?? order.Status;
        await _dbContext.SaveChangesAsync();

        return Ok(order);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteOrder(string id)
    {
        var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
        if (order == null)
        {
            return NotFound(new { error = "Order not found" });
        }

        var authResult = await _authzService.AuthorizeAsync(User, order, ResourceOperation.Delete);
        if (!authResult.Succeeded)
        {
            return NotFound(new { error = "Order not found" });
        }

        _dbContext.Orders.Remove(order);
        await _dbContext.SaveChangesAsync();

        return NoContent();
    }
}

public record CreateOrderRequest(decimal TotalAmount, string Description);
public record UpdateOrderRequest(string? Description, string? Status);
