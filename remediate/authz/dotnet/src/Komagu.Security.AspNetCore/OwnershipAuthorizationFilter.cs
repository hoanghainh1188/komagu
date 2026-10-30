namespace Komagu.Security.AspNetCore;

using Komagu.Security.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Action filter enforcing ownership verification and returning HTTP 404 Not Found on mismatch.
/// </summary>
public sealed class OwnershipAuthorizationFilter : IAsyncActionFilter
{
    private readonly Type _resourceType;
    private readonly string _idRouteParameter;
    private readonly ResourceOperation _operation;
    private readonly IKomaguAuthorizationService _authorizationService;

    public OwnershipAuthorizationFilter(
        Type resourceType,
        string idRouteParameter,
        ResourceOperation operation,
        IKomaguAuthorizationService authorizationService)
    {
        _resourceType = resourceType ?? throw new ArgumentNullException(nameof(resourceType));
        _idRouteParameter = idRouteParameter ?? throw new ArgumentNullException(nameof(idRouteParameter));
        _operation = operation;
        _authorizationService = authorizationService ?? throw new ArgumentNullException(nameof(authorizationService));
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var user = context.HttpContext.User;

        // Invariant: Anonymous callers must be denied with HTTP 404 immediately before execution
        if (user?.Identity?.IsAuthenticated != true)
        {
            context.Result = new NotFoundResult();
            return;
        }

        // Collect the id from the route and from bound arguments; disagreeing values are denied so the
        // filter can never check one id while the action uses another (e.g. route {id} vs [FromQuery] id).
        context.RouteData.Values.TryGetValue(_idRouteParameter, out var routeId);
        context.ActionArguments.TryGetValue(_idRouteParameter, out var argId);
        if (routeId != null && argId != null &&
            !string.Equals(routeId.ToString(), argId.ToString(), StringComparison.Ordinal))
        {
            context.Result = new NotFoundResult();
            return;
        }

        var rawId = routeId ?? argId;
        var subjectResources = context.ActionArguments.Values
            .Where(v => v != null && _resourceType.IsInstanceOfType(v))
            .Cast<object>()
            .ToList();
        var resourcesToAuthorize = new List<object>();

        if (rawId != null)
        {
            // ID-addressed operation: Must resolve resource server-side via IKomaguResourceResolver.
            // Client-supplied body/action objects MUST NOT be used as the authorization subject for an ID-addressed operation.
            var resolver = context.HttpContext.RequestServices.GetService<IKomaguResourceResolver>();
            if (resolver == null)
            {
                // Fail-closed: No resolver registered to resolve the target resource
                context.Result = new NotFoundResult();
                return;
            }

            object? resource;
            try
            {
                resource = await resolver.ResolveAsync(_resourceType, rawId.ToString()!, context.HttpContext.RequestAborted);
            }
            catch (Exception) when (!context.HttpContext.RequestAborted.IsCancellationRequested)
            {
                // Fail-closed with the same 404 as a missing resource (no 500 / no existence oracle)
                resource = null;
            }

            if (resource == null)
            {
                // Fail-closed: Resolver returned null (resource does not exist or unauthorized)
                context.Result = new NotFoundResult();
                return;
            }

            // A bound object of the resource type must describe the same resource: same id when it carries
            // one, and no change of owner or tenant. Otherwise the action could act on body.Id or re-own data.
            if (subjectResources.Any(arg => !DescribesSameResource(arg, resource, rawId)))
            {
                context.Result = new NotFoundResult();
                return;
            }

            resourcesToAuthorize.Add(resource);
        }
        else
        {
            // No id under the configured parameter name. Mutations are id-addressed by definition, so a
            // missing id means a misconfigured idRouteParameter (e.g. route {docId}) — never fall back to
            // authorizing a client-supplied object for Update/Delete.
            if (_operation == ResourceOperation.Update || _operation == ResourceOperation.Delete)
            {
                context.Result = new NotFoundResult();
                return;
            }

            // Create / non-id Read: every resource-typed argument must be authorized, not just the first.
            resourcesToAuthorize.AddRange(subjectResources);
        }

        // Fail-closed: If resource could not be resolved from arguments or resolver, deny with 404
        if (resourcesToAuthorize.Count == 0)
        {
            context.Result = new NotFoundResult();
            return;
        }

        // Authorize caller against every resolved resource strictly before executing action
        foreach (var resource in resourcesToAuthorize)
        {
            var authResult = await _authorizationService.AuthorizeAsync(
                user,
                resource,
                _operation,
                context.HttpContext.RequestAborted);

            if (!authResult.Succeeded)
            {
                // Invariant: Deny by default with HTTP 404 Not Found to eliminate ID enumeration
                context.Result = new NotFoundResult();
                return;
            }
        }

        // Proceed to execute the action
        var executedContext = await next();

        // If the action returned an ObjectResult, perform post-execution verification if needed
        if (executedContext.Result is ObjectResult objectResult && objectResult.Value != null)
        {
            if (_resourceType.IsInstanceOfType(objectResult.Value))
            {
                var postAuthResult = await _authorizationService.AuthorizeAsync(
                    user,
                    objectResult.Value,
                    _operation,
                    context.HttpContext.RequestAborted);

                if (!postAuthResult.Succeeded)
                {
                    // Intercept and rewrite response to 404 Not Found
                    executedContext.Result = new NotFoundResult();
                }
            }
        }
    }

    private static bool DescribesSameResource(object candidate, object resolved, object routeId)
    {
        var candidateId = ReadId(candidate);
        if (candidateId != null && !IsDefault(candidateId) &&
            !string.Equals(candidateId.ToString(), routeId.ToString(), StringComparison.Ordinal))
        {
            return false;
        }

        if (candidate is IOwnedResource c && resolved is IOwnedResource r)
        {
            if (!string.IsNullOrEmpty(c.OwnerUserId) && !string.Equals(c.OwnerUserId, r.OwnerUserId, StringComparison.Ordinal))
            {
                return false;
            }

            if (!string.IsNullOrEmpty(c.TenantId) && !string.Equals(c.TenantId, r.TenantId, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static object? ReadId(object value)
    {
        var ownedInterface = value.GetType().GetInterfaces()
            .FirstOrDefault(i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(IOwnedResource<>));
        var property = ownedInterface?.GetProperty("Id") ?? value.GetType().GetProperty("Id");
        return property?.GetValue(value);
    }

    private static bool IsDefault(object value) =>
        value.GetType().IsValueType && value.Equals(Activator.CreateInstance(value.GetType()));
}
