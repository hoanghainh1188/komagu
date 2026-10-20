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
        ClaimsPrincipal? user,
        Dictionary<string, object?>? actionArgs = null,
        Dictionary<string, object?>? routeValues = null,
        IServiceProvider? serviceProvider = null)
    {
        var httpContext = new DefaultHttpContext { User = user ?? new ClaimsPrincipal(new ClaimsIdentity()) };
        if (serviceProvider != null)
        {
            httpContext.RequestServices = serviceProvider;
        }

        var routeData = new RouteData();
        if (routeValues != null)
        {
            foreach (var (k, v) in routeValues)
            {
                routeData.Values[k] = v;
            }
        }

        var actionContext = new ActionContext(httpContext, routeData, new ActionDescriptor());

        var executingContext = new ActionExecutingContext(
            actionContext,
            new List<IFilterMetadata>(),
            actionArgs ?? new Dictionary<string, object?>(),
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

    [Fact]
    public async Task Filter_WhenCallerIsAnonymous_ReturnsHttp404NotFoundAndDoesNotInvokeNext()
    {
        // Arrange: Unauthenticated caller should fail-closed with 404 before execution
        var anonymousUser = new ClaimsPrincipal(new ClaimsIdentity());
        var doc = new SampleDocument(Guid.NewGuid(), "user-1", "tenant-1", "Public Note");
        var (executingContext, nextDelegate) = CreateActionContext(anonymousUser, new Dictionary<string, object?> { ["doc"] = doc });

        var authService = new DefaultKomainuAuthorizationService(Mock.Of<ISecurityAuditSink>());
        var filter = new OwnershipAuthorizationFilter(typeof(SampleDocument), "id", ResourceOperation.Read, authService);

        // Act
        await filter.OnActionExecutionAsync(executingContext, nextDelegate.Object);

        // Assert
        nextDelegate.Verify(d => d(), Times.Never);
        Assert.NotNull(executingContext.Result);
        Assert.IsType<NotFoundResult>(executingContext.Result);
    }

    [Fact]
    public async Task Filter_WhenResourceUnresolved_ReturnsHttp404NotFoundAndDoesNotInvokeNext()
    {
        // Arrange: When action arguments and route data cannot produce a resource, fail-closed with 404
        var user = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "valid-user"),
            new Claim("tenant_id", "tenant-1")
        ], "TestAuth"));

        var (executingContext, nextDelegate) = CreateActionContext(user, new Dictionary<string, object?>());

        var authService = new DefaultKomainuAuthorizationService(Mock.Of<ISecurityAuditSink>());
        var filter = new OwnershipAuthorizationFilter(typeof(SampleDocument), "id", ResourceOperation.Read, authService);

        // Act
        await filter.OnActionExecutionAsync(executingContext, nextDelegate.Object);

        // Assert
        nextDelegate.Verify(d => d(), Times.Never);
        Assert.NotNull(executingContext.Result);
        Assert.IsType<NotFoundResult>(executingContext.Result);
    }

    [Fact]
    public async Task Filter_WhenNoResolverRegistered_ReturnsHttp404NotFoundAndDoesNotInvokeNext()
    {
        // Arrange: Route parameter exists but no IKomainuResourceResolver is registered in DI
        var user = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "valid-user"),
            new Claim("tenant_id", "tenant-1")
        ], "TestAuth"));

        var spMock = new Mock<IServiceProvider>();
        spMock.Setup(sp => sp.GetService(typeof(IKomainuResourceResolver))).Returns((object?)null);

        var (executingContext, nextDelegate) = CreateActionContext(
            user,
            routeValues: new Dictionary<string, object?> { ["id"] = Guid.NewGuid().ToString() },
            serviceProvider: spMock.Object);

        var authService = new DefaultKomainuAuthorizationService(Mock.Of<ISecurityAuditSink>());
        var filter = new OwnershipAuthorizationFilter(typeof(SampleDocument), "id", ResourceOperation.Read, authService);

        // Act
        await filter.OnActionExecutionAsync(executingContext, nextDelegate.Object);

        // Assert
        nextDelegate.Verify(d => d(), Times.Never);
        Assert.NotNull(executingContext.Result);
        Assert.IsType<NotFoundResult>(executingContext.Result);
    }

    [Fact]
    public async Task Filter_WhenResolverReturnsNull_ReturnsHttp404NotFoundAndDoesNotInvokeNext()
    {
        // Arrange: Resolver is registered but returns null for the given resource ID
        var user = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "valid-user"),
            new Claim("tenant_id", "tenant-1")
        ], "TestAuth"));

        var resolverMock = new Mock<IKomainuResourceResolver>();
        resolverMock.Setup(r => r.ResolveAsync(typeof(SampleDocument), "doc-999", It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);

        var spMock = new Mock<IServiceProvider>();
        spMock.Setup(sp => sp.GetService(typeof(IKomainuResourceResolver))).Returns(resolverMock.Object);

        var (executingContext, nextDelegate) = CreateActionContext(
            user,
            routeValues: new Dictionary<string, object?> { ["id"] = "doc-999" },
            serviceProvider: spMock.Object);

        var authService = new DefaultKomainuAuthorizationService(Mock.Of<ISecurityAuditSink>());
        var filter = new OwnershipAuthorizationFilter(typeof(SampleDocument), "id", ResourceOperation.Read, authService);

        // Act
        await filter.OnActionExecutionAsync(executingContext, nextDelegate.Object);

        // Assert
        nextDelegate.Verify(d => d(), Times.Never);
        Assert.NotNull(executingContext.Result);
        Assert.IsType<NotFoundResult>(executingContext.Result);
    }

    [Fact]
    public async Task Filter_WhenResolverResolvesOwner_InvokesNextAction()
    {
        // Arrange: Resolver resolves resource matching caller -> action proceeds
        var docId = Guid.NewGuid();
        var user = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "valid-user"),
            new Claim("tenant_id", "tenant-1")
        ], "TestAuth"));

        var doc = new SampleDocument(docId, "valid-user", "tenant-1", "Resolved Doc");
        var resolverMock = new Mock<IKomainuResourceResolver>();
        resolverMock.Setup(r => r.ResolveAsync(typeof(SampleDocument), docId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(doc);

        var spMock = new Mock<IServiceProvider>();
        spMock.Setup(sp => sp.GetService(typeof(IKomainuResourceResolver))).Returns(resolverMock.Object);

        var (executingContext, nextDelegate) = CreateActionContext(
            user,
            routeValues: new Dictionary<string, object?> { ["id"] = docId.ToString() },
            serviceProvider: spMock.Object);

        var authService = new DefaultKomainuAuthorizationService(Mock.Of<ISecurityAuditSink>());
        var filter = new OwnershipAuthorizationFilter(typeof(SampleDocument), "id", ResourceOperation.Read, authService);

        // Act
        await filter.OnActionExecutionAsync(executingContext, nextDelegate.Object);

        // Assert: Authorization succeeded before execution, next was invoked
        nextDelegate.Verify(d => d(), Times.Once);
        Assert.Null(executingContext.Result);
    }

    [Fact]
    public async Task Filter_WhenRouteIdPresent_IgnoresAttackerOwnedBodyObject_AndFailsClosedOnVictimResource()
    {
        // Arrange: Invariant from Issue #206:
        // Attacker calls PUT/POST /docs/{victimId} with body containing attacker's own document.
        // The filter MUST resolve the route ID server-side and verify caller against the victim's resource,
        // strictly ignoring the attacker-controlled body object as an authorization subject.
        var victimDocId = Guid.NewGuid();
        var attacker = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "attacker-user"),
            new Claim("tenant_id", "tenant-1")
        ], "TestAuth"));

        var victimDoc = new SampleDocument(victimDocId, "victim-user", "tenant-1", "Victim Private Doc");
        var attackerOwnedBodyDoc = new SampleDocument(Guid.NewGuid(), "attacker-user", "tenant-1", "Attacker Body Doc");

        var resolverMock = new Mock<IKomainuResourceResolver>();
        resolverMock.Setup(r => r.ResolveAsync(typeof(SampleDocument), victimDocId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(victimDoc);

        var spMock = new Mock<IServiceProvider>();
        spMock.Setup(sp => sp.GetService(typeof(IKomainuResourceResolver))).Returns(resolverMock.Object);

        var (executingContext, nextDelegate) = CreateActionContext(
            attacker,
            actionArgs: new Dictionary<string, object?> { ["doc"] = attackerOwnedBodyDoc },
            routeValues: new Dictionary<string, object?> { ["id"] = victimDocId.ToString() },
            serviceProvider: spMock.Object);

        var authService = new DefaultKomainuAuthorizationService(Mock.Of<ISecurityAuditSink>());
        var filter = new OwnershipAuthorizationFilter(typeof(SampleDocument), "id", ResourceOperation.Update, authService);

        // Act
        await filter.OnActionExecutionAsync(executingContext, nextDelegate.Object);

        // Assert: Access denied with 404, next() handler MUST NOT be executed
        nextDelegate.Verify(d => d(), Times.Never);
        Assert.NotNull(executingContext.Result);
        Assert.IsType<NotFoundResult>(executingContext.Result);
        resolverMock.Verify(r => r.ResolveAsync(typeof(SampleDocument), victimDocId.ToString(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Filter_WhenRouteIdPresent_ResolverReturnsNull_IgnoresAttackerOwnedBodyObject_AndReturnsNotFound()
    {
        // Arrange: Route ID points to non-existent or inaccessible resource, but body contains attacker's owned resource
        var requestedDocId = Guid.NewGuid();
        var attacker = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "attacker-user"),
            new Claim("tenant_id", "tenant-1")
        ], "TestAuth"));

        var attackerOwnedBodyDoc = new SampleDocument(Guid.NewGuid(), "attacker-user", "tenant-1", "Attacker Body Doc");

        var resolverMock = new Mock<IKomainuResourceResolver>();
        resolverMock.Setup(r => r.ResolveAsync(typeof(SampleDocument), requestedDocId.ToString(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((object?)null);

        var spMock = new Mock<IServiceProvider>();
        spMock.Setup(sp => sp.GetService(typeof(IKomainuResourceResolver))).Returns(resolverMock.Object);

        var (executingContext, nextDelegate) = CreateActionContext(
            attacker,
            actionArgs: new Dictionary<string, object?> { ["doc"] = attackerOwnedBodyDoc },
            routeValues: new Dictionary<string, object?> { ["id"] = requestedDocId.ToString() },
            serviceProvider: spMock.Object);

        var authService = new DefaultKomainuAuthorizationService(Mock.Of<ISecurityAuditSink>());
        var filter = new OwnershipAuthorizationFilter(typeof(SampleDocument), "id", ResourceOperation.Update, authService);

        // Act
        await filter.OnActionExecutionAsync(executingContext, nextDelegate.Object);

        // Assert: Must fail-closed with 404 and NEVER invoke next()
        nextDelegate.Verify(d => d(), Times.Never);
        Assert.NotNull(executingContext.Result);
        Assert.IsType<NotFoundResult>(executingContext.Result);
    }
}
