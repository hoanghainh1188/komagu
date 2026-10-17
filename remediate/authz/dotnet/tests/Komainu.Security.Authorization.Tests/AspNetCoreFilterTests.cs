namespace Komainu.Security.Authorization.Tests;

using System.Security.Claims;
using Komainu.Security.AspNetCore;
using Komainu.Security.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Moq;
using Xunit;

public class AspNetCoreFilterTests
{
    public record SampleDocument(Guid Id, string OwnerUserId, string TenantId, string Title) : IOwnedResource<Guid>, IOwnedResource;

    private static (ActionExecutingContext ExecutingContext, Mock<ActionExecutionDelegate> NextDelegate) CreateActionContext(
        ClaimsPrincipal user,
        Dictionary<string, object?> actionArgs)
    {
        var httpContext = new DefaultHttpContext { User = user };
        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());

        var executingContext = new ActionExecutingContext(
            actionContext,
            new List<IFilterMetadata>(),
            actionArgs,
            new object());

        var nextDelegate = new Mock<ActionExecutionDelegate>();
        nextDelegate.Setup(d => d()).ReturnsAsync(new ActionExecutedContext(
            actionContext,
            new List<IFilterMetadata>(),
            new object())
        {
            Result = new OkObjectResult("success")
        });

        return (executingContext, nextDelegate);
    }

    [Fact]
    public async Task Filter_WhenResourceOwnerMatches_InvokesNextAction()
    {
        // Arrange
        var user = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "valid-user"),
            new Claim("tenant_id", "tenant-1")
        ], "TestAuth"));

        var doc = new SampleDocument(Guid.NewGuid(), "valid-user", "tenant-1", "Report 2026");
        var (executingContext, nextDelegate) = CreateActionContext(user, new Dictionary<string, object?> { ["doc"] = doc });

        var authService = new DefaultKomainuAuthorizationService(Mock.Of<ISecurityAuditSink>());
        var filter = new OwnershipAuthorizationFilter(typeof(SampleDocument), "id", ResourceOperation.Read, authService);

        // Act
        await filter.OnActionExecutionAsync(executingContext, nextDelegate.Object);

        // Assert: Succeeded, so next() was invoked and context.Result was not overwritten with 404
        nextDelegate.Verify(d => d(), Times.Once);
        Assert.Null(executingContext.Result);
    }

    [Fact]
    public async Task Filter_WhenResourceOwnerMismatches_ReturnsHttp404NotFound()
    {
        // Arrange: Invariant: Deny by default with HTTP 404 Not Found to prevent ID enumeration
        var attacker = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "attacker-id"),
            new Claim("tenant_id", "tenant-1")
        ], "TestAuth"));

        var victimDoc = new SampleDocument(Guid.NewGuid(), "victim-id", "tenant-1", "Confidential Strategy");
        var (executingContext, nextDelegate) = CreateActionContext(attacker, new Dictionary<string, object?> { ["doc"] = victimDoc });

        var authService = new DefaultKomainuAuthorizationService(Mock.Of<ISecurityAuditSink>());
        var filter = new OwnershipAuthorizationFilter(typeof(SampleDocument), "id", ResourceOperation.Read, authService);

        // Act
        await filter.OnActionExecutionAsync(executingContext, nextDelegate.Object);

        // Assert
        nextDelegate.Verify(d => d(), Times.Never);
        Assert.NotNull(executingContext.Result);
        Assert.IsType<NotFoundResult>(executingContext.Result);
    }
}
