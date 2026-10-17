namespace Komainu.Security.Authorization.Tests;

using System.Security.Claims;
using Komainu.Security.Authorization;
using Moq;
using Xunit;

public class AuthorizationServiceTests
{
    private readonly Mock<ISecurityAuditSink> _mockAuditSink;
    private readonly DefaultKomainuAuthorizationService _service;

    public AuthorizationServiceTests()
    {
        _mockAuditSink = new Mock<ISecurityAuditSink>();
        _service = new DefaultKomainuAuthorizationService(_mockAuditSink.Object);
    }

    private static ClaimsPrincipal CreateUser(string userId, string tenantId)
    {
        var claims = new[]
        {
            new Claim("sub", userId),
            new Claim("tenant_id", tenantId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        return new ClaimsPrincipal(identity);
    }

    public record TestOrder(Guid Id, string OwnerUserId, string TenantId, decimal Amount) : IOwnedResource<Guid>, IOwnedResource;

    [Fact]
    public async Task AuthorizeAsync_WhenUserOwnsResourceInSameTenant_ReturnsSuccess()
    {
        // Arrange
        var user = CreateUser("user-123", "tenant-alpha");
        var order = new TestOrder(Guid.NewGuid(), "user-123", "tenant-alpha", 1500m);

        // Act
        var result = await _service.AuthorizeAsync(user, order, ResourceOperation.Read);

        // Assert
        Assert.True(result.Succeeded);
        Assert.Null(result.FailureReason);
        _mockAuditSink.Verify(s => s.EmitAsync(It.IsAny<SecurityAuditEvent>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task AuthorizeAsync_WhenUserAttemptsAccessToAnotherUsersResource_ReturnsDeniedAndEmitsAudit()
    {
        // Arrange
        var attacker = CreateUser("attacker-999", "tenant-alpha");
        var victimOrder = new TestOrder(Guid.NewGuid(), "victim-123", "tenant-alpha", 50000m);

        // Act
        var result = await _service.AuthorizeAsync(attacker, victimOrder, ResourceOperation.Read);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Contains("User ownership violation", result.FailureReason);

        _mockAuditSink.Verify(s => s.EmitAsync(
            It.Is<SecurityAuditEvent>(e =>
                e.ActorUserId == "attacker-999" &&
                e.ActorTenantId == "tenant-alpha" &&
                e.ResourceType == nameof(TestOrder) &&
                e.ResourceId == victimOrder.Id.ToString() &&
                e.Operation == ResourceOperation.Read &&
                e.Reason.Contains("User ownership violation")),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task AuthorizeAsync_WhenCrossTenantAccessAttempted_ReturnsDeniedAndEmitsAudit()
    {
        // Arrange
        var crossTenantUser = CreateUser("user-123", "tenant-beta");
        var targetOrder = new TestOrder(Guid.NewGuid(), "user-123", "tenant-alpha", 200m);

        // Act
        var result = await _service.AuthorizeAsync(crossTenantUser, targetOrder, ResourceOperation.Read);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Contains("Tenant boundary violation", result.FailureReason);

        _mockAuditSink.Verify(s => s.EmitAsync(
            It.Is<SecurityAuditEvent>(e =>
                e.ActorUserId == "user-123" &&
                e.ActorTenantId == "tenant-beta" &&
                e.Reason.Contains("Tenant boundary violation")),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task AuthorizeAsync_WhenUserIsUnauthenticated_ReturnsDeniedAndEmitsAudit()
    {
        // Arrange
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
        var order = new TestOrder(Guid.NewGuid(), "user-123", "tenant-alpha", 100m);

        // Act
        var result = await _service.AuthorizeAsync(anonymous, order, ResourceOperation.Read);

        // Assert
        Assert.False(result.Succeeded);
        Assert.Contains("unauthenticated", result.FailureReason, StringComparison.OrdinalIgnoreCase);
        _mockAuditSink.Verify(s => s.EmitAsync(It.IsAny<SecurityAuditEvent>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public void GetCurrentUserId_ExtractsSubClaim_Correctly()
    {
        var user = CreateUser("user-abc", "tenant-xyz");
        Assert.Equal("user-abc", _service.GetCurrentUserId(user));
    }

    [Fact]
    public void GetCurrentTenantId_ExtractsTenantClaim_Correctly()
    {
        var user = CreateUser("user-abc", "tenant-xyz");
        Assert.Equal("tenant-xyz", _service.GetCurrentTenantId(user));
    }

    [Fact]
    public void GetCurrentUserId_ThrowsUnauthorized_WhenClaimMissing()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("foo", "bar")], "Auth"));
        Assert.Throws<UnauthorizedAccessException>(() => _service.GetCurrentUserId(user));
    }
}
