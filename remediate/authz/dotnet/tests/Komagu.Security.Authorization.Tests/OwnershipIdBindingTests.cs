namespace Komagu.Security.Authorization.Tests;

using System.Security.Claims;
using Komagu.Security.AspNetCore;
using Komagu.Security.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Moq;
using Xunit;

/// <summary>
/// Regression tests for #221: the resource id must be resolved server-side, and client-supplied
/// objects must never stand in for it or disagree with it.
/// </summary>
public class OwnershipIdBindingTests
{
    public record Doc(Guid Id, string OwnerUserId, string TenantId, string Title) : IOwnedResource<Guid>, IOwnedResource;

    private static readonly ClaimsPrincipal Attacker = new(new ClaimsIdentity(
    [
        new Claim("sub", "attacker-user"),
        new Claim("tenant_id", "tenant-1")
    ], "TestAuth"));

    private readonly Doc _attackerDoc = new(Guid.NewGuid(), "attacker-user", "tenant-1", "Attacker Doc");
    private readonly Doc _victimDoc = new(Guid.NewGuid(), "victim-user", "tenant-1", "Victim Doc");

    private (ActionExecutingContext Context, Mock<ActionExecutionDelegate> Next) Context(
        Dictionary<string, object?> actionArgs,
        Dictionary<string, object?>? routeValues = null,
        IKomaguResourceResolver? resolver = null)
    {
        var services = new Mock<IServiceProvider>();
        services.Setup(sp => sp.GetService(typeof(IKomaguResourceResolver))).Returns(resolver ?? DefaultResolver());
        var httpContext = new DefaultHttpContext { User = Attacker, RequestServices = services.Object };

        var routeData = new RouteData();
        foreach (var (k, v) in routeValues ?? new Dictionary<string, object?>())
        {
            routeData.Values[k] = v;
        }

        var actionContext = new ActionContext(httpContext, routeData, new ActionDescriptor());
        var executing = new ActionExecutingContext(actionContext, new List<IFilterMetadata>(), actionArgs, new object());
        var next = new Mock<ActionExecutionDelegate>();
        next.Setup(d => d()).ReturnsAsync(new ActionExecutedContext(actionContext, new List<IFilterMetadata>(), new object())
        {
            Result = new OkObjectResult("success")
        });
        return (executing, next);
    }

    private IKomaguResourceResolver DefaultResolver()
    {
        var resolver = new Mock<IKomaguResourceResolver>();
        resolver.Setup(r => r.ResolveAsync(typeof(Doc), _attackerDoc.Id.ToString(), It.IsAny<CancellationToken>())).ReturnsAsync(_attackerDoc);
        resolver.Setup(r => r.ResolveAsync(typeof(Doc), _victimDoc.Id.ToString(), It.IsAny<CancellationToken>())).ReturnsAsync(_victimDoc);
        return resolver.Object;
    }

    private static OwnershipAuthorizationFilter Filter(ResourceOperation op, string idParameter = "id") =>
        new(typeof(Doc), idParameter, op, new DefaultKomaguAuthorizationService(Mock.Of<ISecurityAuditSink>()));

    private static async Task AssertDenied(OwnershipAuthorizationFilter filter, ActionExecutingContext ctx, Mock<ActionExecutionDelegate> next)
    {
        await filter.OnActionExecutionAsync(ctx, next.Object);
        next.Verify(d => d(), Times.Never);
        Assert.IsType<NotFoundResult>(ctx.Result);
    }

    [Theory]
    [InlineData(ResourceOperation.Update)]
    [InlineData(ResourceOperation.Delete)]
    public async Task Mutation_WhenIdParameterNameDoesNotMatchRoute_DeniesInsteadOfTrustingBody(ResourceOperation op)
    {
        // PUT /docs/{docId} with the default idRouteParameter "id" and an attacker-owned body.
        var (ctx, next) = Context(
            new Dictionary<string, object?> { ["docId"] = _victimDoc.Id.ToString(), ["body"] = _attackerDoc },
            new Dictionary<string, object?> { ["docId"] = _victimDoc.Id.ToString() });

        await AssertDenied(Filter(op), ctx, next);
    }

    [Fact]
    public async Task Update_WhenBodyIdDiffersFromResolvedResource_Denies()
    {
        // Route id is the attacker's own doc; the body targets the victim's doc.
        var body = _attackerDoc with { Id = _victimDoc.Id };
        var (ctx, next) = Context(
            new Dictionary<string, object?> { ["body"] = body },
            new Dictionary<string, object?> { ["id"] = _attackerDoc.Id.ToString() });

        await AssertDenied(Filter(ResourceOperation.Update), ctx, next);
    }

    [Fact]
    public async Task Update_WhenBodyChangesOwner_Denies()
    {
        var body = _attackerDoc with { OwnerUserId = "victim-user" };
        var (ctx, next) = Context(
            new Dictionary<string, object?> { ["body"] = body },
            new Dictionary<string, object?> { ["id"] = _attackerDoc.Id.ToString() });

        await AssertDenied(Filter(ResourceOperation.Update), ctx, next);
    }

    [Fact]
    public async Task Update_WhenBodyMatchesResolvedResource_InvokesAction()
    {
        var body = _attackerDoc with { Title = "Renamed" };
        var (ctx, next) = Context(
            new Dictionary<string, object?> { ["body"] = body },
            new Dictionary<string, object?> { ["id"] = _attackerDoc.Id.ToString() });

        await Filter(ResourceOperation.Update).OnActionExecutionAsync(ctx, next.Object);
        next.Verify(d => d(), Times.Once);
    }

    [Fact]
    public async Task WhenRouteIdAndArgumentIdDisagree_Denies()
    {
        // Route {id} is the attacker's own doc while a [FromQuery] id argument names the victim's doc.
        var (ctx, next) = Context(
            new Dictionary<string, object?> { ["id"] = _victimDoc.Id.ToString() },
            new Dictionary<string, object?> { ["id"] = _attackerDoc.Id.ToString() });

        await AssertDenied(Filter(ResourceOperation.Read), ctx, next);
    }

    [Fact]
    public async Task Create_ChecksEveryResourceArgument()
    {
        var (ctx, next) = Context(new Dictionary<string, object?> { ["mine"] = _attackerDoc, ["theirs"] = _victimDoc });

        await AssertDenied(Filter(ResourceOperation.Create), ctx, next);
    }

    [Fact]
    public async Task WhenResolverThrows_Denies404()
    {
        var resolver = new Mock<IKomaguResourceResolver>();
        resolver.Setup(r => r.ResolveAsync(It.IsAny<Type>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("db down"));
        var (ctx, next) = Context(
            new Dictionary<string, object?>(),
            new Dictionary<string, object?> { ["id"] = _attackerDoc.Id.ToString() },
            resolver.Object);

        await AssertDenied(Filter(ResourceOperation.Read), ctx, next);
    }
}
