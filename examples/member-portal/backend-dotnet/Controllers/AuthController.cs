namespace MemberPortal.Backend.Controllers;

using MemberPortal.Backend.Models;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/v1/auth")]
public class AuthController : ControllerBase
{
    private static readonly List<PersonaDto> Personas = new()
    {
        new PersonaDto(
            UserId: "user-a",
            DisplayName: "Alice (User A)",
            TenantId: "tenant-alpha",
            TenantName: "Alpha Corporation",
            Role: "member",
            MockToken: "token-user-a"
        ),
        new PersonaDto(
            UserId: "user-b",
            DisplayName: "Bob (User B - Attacker/Peer)",
            TenantId: "tenant-alpha",
            TenantName: "Alpha Corporation",
            Role: "member",
            MockToken: "token-user-b"
        ),
        new PersonaDto(
            UserId: "user-c",
            DisplayName: "Charlie (User C - Cross-Tenant)",
            TenantId: "tenant-beta",
            TenantName: "Beta Holdings",
            Role: "member",
            MockToken: "token-user-c"
        ),
    };

    [HttpGet("personas")]
    public ActionResult<List<PersonaDto>> GetPersonas()
    {
        return Ok(Personas);
    }
}
