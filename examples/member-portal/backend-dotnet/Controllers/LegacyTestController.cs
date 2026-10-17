namespace MemberPortal.Backend.Controllers;

using MemberPortal.Backend.Data;
using MemberPortal.Backend.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Planted vulnerability endpoints for D5 continuous security testing and verification.
/// Active only when ENABLE_SECURITY_TEST_VULNERABILITIES is set to "true".
/// </summary>
[ApiController]
[Route("api/v1/test")]
public class LegacyTestController : ControllerBase
{
    private readonly PortalDbContext _dbContext;
    private readonly bool _vulnerabilitiesEnabled;

    public LegacyTestController(PortalDbContext dbContext, IConfiguration configuration)
    {
        _dbContext = dbContext;
        var envVal = Environment.GetEnvironmentVariable("ENABLE_SECURITY_TEST_VULNERABILITIES");
        _vulnerabilitiesEnabled = string.Equals(envVal, "true", StringComparison.OrdinalIgnoreCase)
            || configuration.GetValue<bool>("EnableSecurityTestVulnerabilities", true);
    }

    [HttpGet("legacy-orders/{id}")]
    public async Task<ActionResult<Order>> GetLegacyOrder(string id)
    {
        if (!_vulnerabilitiesEnabled)
        {
            return NotFound(new { error = "Test endpoints disabled in production mode" });
        }

        // PLANT-BOLA: Direct query by ID with no user or tenant scoping
        var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
        if (order == null)
        {
            return NotFound(new { error = "Order not found" });
        }

        // Return 200 OK to attacker -> BOLA breach!
        return Ok(order);
    }

    [HttpPut("legacy-orders/{id}")]
    public async Task<ActionResult<Order>> UpdateLegacyOrder(string id, [FromBody] UpdateOrderRequest request)
    {
        if (!_vulnerabilitiesEnabled)
        {
            return NotFound(new { error = "Test endpoints disabled in production mode" });
        }

        // PLANT-BOLA: Direct modification of any order without verifying caller
        var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
        if (order == null)
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
        if (!_vulnerabilitiesEnabled)
        {
            return NotFound(new { error = "Test endpoints disabled in production mode" });
        }

        // PLANT-BOLA: Cross-user deletion allowed
        var order = await _dbContext.Orders.FirstOrDefaultAsync(o => o.Id == id);
        if (order == null)
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
        if (!_vulnerabilitiesEnabled)
        {
            return NotFound(new { error = "Test endpoints disabled in production mode" });
        }

        // PLANT-SQLI: Raw SQL string interpolation / concatenation
        var rawSql = $"SELECT * FROM Orders WHERE Description LIKE '%{query}%'";
        var results = await _dbContext.Orders.FromSqlRaw(rawSql).ToListAsync();
        return Ok(results);
    }
}
