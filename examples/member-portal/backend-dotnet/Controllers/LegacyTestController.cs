namespace MemberPortal.Backend.Controllers;

using MemberPortal.Backend.Data;
using MemberPortal.Backend.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Komagu.Security.Authorization;

/// <summary>
/// Legacy endpoints for continuous security testing and verification.
/// Supports both legacy/vulnerable mode (ENABLE_SECURITY_TEST_VULNERABILITIES=true)
/// and modernized remediated mode using Komagu D1 Authorization & D3 Safe Queries.
/// </summary>
[ApiController]
[Route("api/v1/test")]
public class LegacyTestController : ControllerBase
{
    private readonly PortalDbContext _dbContext;
    private readonly IKomaguAuthorizationService _authzService;
    private readonly bool _vulnerabilitiesEnabled;

    public LegacyTestController(
        PortalDbContext dbContext,
        IKomaguAuthorizationService authzService,
        IConfiguration configuration)
    {
        _dbContext = dbContext;
        _authzService = authzService;
        var envVal = Environment.GetEnvironmentVariable("ENABLE_SECURITY_TEST_VULNERABILITIES");
        _vulnerabilitiesEnabled = string.Equals(envVal, "true", StringComparison.OrdinalIgnoreCase)
            || configuration.GetValue<bool>("EnableSecurityTestVulnerabilities", false);
    }

    [HttpGet("legacy-orders/{id}")]
    public async Task<ActionResult<Order>> GetLegacyOrder(string id)
    {
        if (_vulnerabilitiesEnabled)
        {
            // PLANT-BOLA: Direct query by ID with no user or tenant scoping
            var vulnOrder = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
            if (vulnOrder == null)
            {
                return NotFound(new { error = "Order not found" });
            }
            return Ok(vulnOrder);
        }

        // REMEDIATED (D1): Enforce object-level ownership check with 404 deny-by-default
        var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
        if (order == null)
        {
            return NotFound(new { error = "Order not found" });
        }

        var authResult = await _authzService.AuthorizeAsync(User, order, ResourceOperation.Read);
        if (!authResult.Succeeded)
        {
            return NotFound(new { error = "Order not found" });
        }

        return Ok(order);
    }

    [HttpPut("legacy-orders/{id}")]
    public async Task<ActionResult<Order>> UpdateLegacyOrder(string id, [FromBody] UpdateOrderRequest request)
    {
        if (_vulnerabilitiesEnabled)
        {
            // PLANT-BOLA: Direct modification of any order without verifying caller
            var vulnOrder = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
            if (vulnOrder == null)
            {
                return NotFound(new { error = "Order not found" });
            }

            vulnOrder.Description = request.Description ?? vulnOrder.Description;
            vulnOrder.Status = request.Status ?? vulnOrder.Status;
            await _dbContext.SaveChangesAsync();

            return Ok(vulnOrder);
        }

        // REMEDIATED (D1): Enforce object-level ownership check on update
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

    [HttpDelete("legacy-orders/{id}")]
    public async Task<IActionResult> DeleteLegacyOrder(string id)
    {
        if (_vulnerabilitiesEnabled)
        {
            // PLANT-BOLA: Cross-user deletion allowed
            var vulnOrder = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
            if (vulnOrder == null)
            {
                return NotFound(new { error = "Order not found" });
            }

            _dbContext.Orders.Remove(vulnOrder);
            await _dbContext.SaveChangesAsync();

            return NoContent();
        }

        // REMEDIATED (D1): Enforce object-level ownership check on delete
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

    [HttpGet("legacy-search")]
    public async Task<ActionResult<List<Order>>> SearchLegacy([FromQuery] string query)
    {
        if (_vulnerabilitiesEnabled)
        {
            // PLANT-SQLI: Raw SQL string interpolation / concatenation
            var rawSql = $"SELECT * FROM Orders WHERE Description LIKE '%{query}%'";
            var rawResults = await _dbContext.Orders.FromSqlRaw(rawSql).ToListAsync();
            return Ok(rawResults);
        }

        // REMEDIATED (D3): Parameterized query preventing SQL injection
        var pattern = $"%{query}%";
        var results = await _dbContext.Orders
            .FromSqlInterpolated($"SELECT * FROM Orders WHERE Description LIKE {pattern}")
            .ToListAsync();
        return Ok(results);
    }
}

