namespace Komagu.Security.Authorization.Tests;

using System.Security.Claims;
using Komagu.Security.AspNetCore;
using Komagu.Security.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Moq;
using Xunit;

public class RoleAuthorizationFilterTests
{
    private static ClaimsPrincipal Authenticated(string roleClaimType = ClaimTypes.Role, params string[] roles)
    {
        var claims = new List<Claim> { new("sub", "user-1"), new("tenant_id", "tenant-1") };
        claims.AddRange(roles.Select(r => new Claim(roleClaimType, r)));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
    }

    private static AuthorizationFilterContext CreateContext(
        ClaimsPrincipal user,
        Dictionary<string, object?>? routeValues = null,
        Action<HttpRequest>? configureRequest = null)
    {
        var httpContext = new DefaultHttpContext { User = user };
        configureRequest?.Invoke(httpContext.Request);

        var routeData = new RouteData();
        foreach (var (k, v) in routeValues ?? new Dictionary<string, object?>())
        {
            routeData.Values[k] = v;
        }

        var actionContext = new ActionContext(httpContext, routeData, new ActionDescriptor { DisplayName = "AdminController.DeleteUser" });
        return new AuthorizationFilterContext(actionContext, new List<IFilterMetadata>());
    }

    private static RoleAuthorizationFilter CreateFilter(
        string[] roles,
        ISecurityAuditSink? sink = null,
        KomaguRoleOptions? options = null)
    {
        sink ??= Mock.Of<ISecurityAuditSink>();
        return new RoleAuthorizationFilter(
            roles,
            sink,
            new DefaultKomaguAuthorizationService(Mock.Of<ISecurityAuditSink>()),
            Options.Create(options ?? new KomaguRoleOptions()));
    }

    [Fact]
    public async Task Filter_WhenCallerHasOneOfRequiredRoles_AllowsRequest()
    {
        var context = CreateContext(Authenticated(ClaimTypes.Role, "support"));
        var filter = CreateFilter(["admin", "support"]);

        await filter.OnAuthorizationAsync(context);

        Assert.Null(context.Result);
    }

    [Fact]
    public async Task Filter_WhenCallerLacksRole_ReturnsHttp403()
    {
        var context = CreateContext(Authenticated(ClaimTypes.Role, "customer"));
        var filter = CreateFilter(["admin"]);

        await filter.OnAuthorizationAsync(context);

        var result = Assert.IsType<StatusCodeResult>(context.Result);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
    }

    [Fact]
    public async Task Filter_RoleMatchIsExactAndOrdinal()
    {
        var context = CreateContext(Authenticated(ClaimTypes.Role, "Admin", "administrator", " admin"));
        var filter = CreateFilter(["admin"]);

        await filter.OnAuthorizationAsync(context);

        Assert.IsType<StatusCodeResult>(context.Result);
    }

    [Fact]
    public async Task Filter_WhenDenyWithNotFound_ReturnsHttp404()
    {
        var context = CreateContext(Authenticated(ClaimTypes.Role, "customer"));
        var filter = CreateFilter(["admin"], options: new KomaguRoleOptions { DenyWith = RoleDenyResponse.NotFound });

        await filter.OnAuthorizationAsync(context);

        Assert.IsType<NotFoundResult>(context.Result);
    }

    [Fact]
    public async Task Filter_WhenCallerIsAnonymous_ReturnsHttp401()
    {
        var context = CreateContext(new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Role, "admin")])));
        var filter = CreateFilter(["admin"]);

        await filter.OnAuthorizationAsync(context);

        Assert.IsType<UnauthorizedResult>(context.Result);
    }

    [Fact]
    public async Task Filter_IgnoresRoleSuppliedInQueryFormRouteAndHeader()
    {
        // Invariant: role=admin in the query string, form, route values or an X-Role header never grants the role
        var context = CreateContext(
            Authenticated(ClaimTypes.Role, "customer"),
            routeValues: new Dictionary<string, object?> { ["role"] = "admin" },
            configureRequest: request =>
            {
                request.QueryString = new QueryString("?role=admin&isAdmin=true");
                request.ContentType = "application/x-www-form-urlencoded";
                request.Form = new FormCollection(new Dictionary<string, StringValues> { ["role"] = "admin" });
                request.Headers["X-Role"] = "admin";
                request.Headers["X-User-Role"] = "admin";
            });
        var filter = CreateFilter(["admin"]);

        await filter.OnAuthorizationAsync(context);

        var result = Assert.IsType<StatusCodeResult>(context.Result);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
    }

    [Fact]
    public async Task Filter_UsesConfiguredRoleClaimType()
    {
        var jwtUser = Authenticated("role", "admin");
        var options = new KomaguRoleOptions { RoleClaimType = "role" };

        var allowed = CreateContext(jwtUser);
        await CreateFilter(["admin"], options: options).OnAuthorizationAsync(allowed);
        Assert.Null(allowed.Result);

        // With the default ClaimTypes.Role the raw "role" claim is not consulted
        var denied = CreateContext(jwtUser);
        await CreateFilter(["admin"]).OnAuthorizationAsync(denied);
        Assert.IsType<StatusCodeResult>(denied.Result);
    }

    [Fact]
    public async Task Filter_OnDenial_EmitsRoleDeniedAuditEvent()
    {
        SecurityAuditEvent? captured = null;
        var sink = new Mock<ISecurityAuditSink>();
        sink.Setup(s => s.EmitAsync(It.IsAny<SecurityAuditEvent>(), It.IsAny<CancellationToken>()))
            .Callback<SecurityAuditEvent, CancellationToken>((e, _) => captured = e)
            .Returns(ValueTask.CompletedTask);

        var context = CreateContext(Authenticated(ClaimTypes.Role, "customer"));
        await CreateFilter(["admin", "auditor"], sink.Object).OnAuthorizationAsync(context);

        sink.Verify(s => s.EmitAsync(It.IsAny<SecurityAuditEvent>(), It.IsAny<CancellationToken>()), Times.Once);
        Assert.NotNull(captured);
        Assert.Equal("Komagu.Authorization.RoleDenied", captured!.EventName);
        Assert.Equal(RoleAuthorizationFilter.RoleDeniedEventName, captured.EventName);
        Assert.Equal("user-1", captured.ActorUserId);
        Assert.Equal("tenant-1", captured.ActorTenantId);
        Assert.Equal("AdminController.DeleteUser", captured.ResourceId);
        Assert.Contains("admin", captured.Reason, StringComparison.Ordinal);
        Assert.Contains("auditor", captured.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Filter_OnAllow_DoesNotEmitAuditEvent()
    {
        var sink = new Mock<ISecurityAuditSink>();
        var context = CreateContext(Authenticated(ClaimTypes.Role, "admin"));

        await CreateFilter(["admin"], sink.Object).OnAuthorizationAsync(context);

        sink.Verify(s => s.EmitAsync(It.IsAny<SecurityAuditEvent>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Filter_WhenAuditSinkThrows_StillDenies()
    {
        var sink = new Mock<ISecurityAuditSink>();
        sink.Setup(s => s.EmitAsync(It.IsAny<SecurityAuditEvent>(), It.IsAny<CancellationToken>()))
            .Throws(new InvalidOperationException("sink down"));
        var context = CreateContext(Authenticated(ClaimTypes.Role, "customer"));

        await CreateFilter(["admin"], sink.Object).OnAuthorizationAsync(context);

        Assert.IsType<StatusCodeResult>(context.Result);
    }

    [Fact]
    public void Attribute_WithNoRoles_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new RequireRoleAttribute());
        Assert.Throws<ArgumentException>(() => new RequireRoleAttribute(Array.Empty<string>()));
        Assert.Throws<ArgumentException>(() => new RequireRoleAttribute("admin", " "));
    }

    [Fact]
    public async Task Attribute_CreatesFilterFromDi_WithConfiguredOptions()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddKomaguAuthorization();
        services.ConfigureKomaguRoles(o =>
        {
            o.RoleClaimType = "role";
            o.DenyWith = RoleDenyResponse.NotFound;
        });
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var attribute = new RequireRoleAttribute("admin");
        Assert.Equal(new[] { "admin" }, attribute.Roles);
        var filter = Assert.IsType<RoleAuthorizationFilter>(attribute.CreateInstance(scope.ServiceProvider));

        var allowed = CreateContext(Authenticated("role", "admin"));
        await filter.OnAuthorizationAsync(allowed);
        Assert.Null(allowed.Result);

        var denied = CreateContext(Authenticated("role", "customer"));
        await filter.OnAuthorizationAsync(denied);
        Assert.IsType<NotFoundResult>(denied.Result);
    }
}
