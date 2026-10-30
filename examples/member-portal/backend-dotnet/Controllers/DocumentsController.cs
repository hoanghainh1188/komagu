namespace MemberPortal.Backend.Controllers;

using MemberPortal.Backend.Data;
using MemberPortal.Backend.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Komagu.Security.Authorization;
using Komagu.Security.EntityFrameworkCore;

[ApiController]
[Route("api/v1/documents")]
public class DocumentsController : ControllerBase
{
    private readonly PortalDbContext _dbContext;
    private readonly IKomaguAuthorizationService _authzService;

    public DocumentsController(PortalDbContext dbContext, IKomaguAuthorizationService authzService)
    {
        _dbContext = dbContext;
        _authzService = authzService;
    }

    [HttpGet]
    public async Task<ActionResult<List<Document>>> ListDocuments()
    {
        var userId = _authzService.GetCurrentUserId(User);
        var tenantId = _authzService.GetCurrentTenantId(User);

        var docs = await _dbContext.Documents
            .WithUserScope<Document, string>(userId, tenantId)
            .OrderByDescending(d => d.CreatedAt)
            .ToListAsync();

        return Ok(docs);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Document>> GetDocument(string id)
    {
        var doc = await _dbContext.Documents.FirstOrDefaultAsync(d => d.Id == id);
        if (doc == null)
        {
            return NotFound(new { error = "Document not found" });
        }

        var authResult = await _authzService.AuthorizeAsync(User, doc, ResourceOperation.Read);
        if (!authResult.Succeeded)
        {
            return NotFound(new { error = "Document not found" });
        }

        return Ok(doc);
    }
}
