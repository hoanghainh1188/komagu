namespace Komainu.Security.AspNetCore;

using Komainu.Security.Authorization;
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
    private readonly IKomainuAuthorizationService _authorizationService;

    public OwnershipAuthorizationFilter(
        Type resourceType,
        string idRouteParameter,
        ResourceOperation operation,
        IKomainuAuthorizationService authorizationService)
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

        // Check if an ID parameter is specified in RouteData or ActionArguments
        object? rawId = null;
        if (context.RouteData.Values.TryGetValue(_idRouteParameter, out var routeId) && routeId != null)
        {
            rawId = routeId;
        }
        else if (context.ActionArguments.TryGetValue(_idRouteParameter, out var argId) && argId != null)
        {
            rawId = argId;
        }

        object? resource = null;

        if (rawId != null)
        {
            // ID-addressed operation: Must resolve resource server-side via IKomainuResourceResolver.
            // Client-supplied body/action objects MUST NOT be used as the authorization subject for an ID-addressed operation.
            var resolver = context.HttpContext.RequestServices.GetService<IKomainuResourceResolver>();
            if (resolver == null)
            {
                // Fail-closed: No resolver registered to resolve the target resource
                context.Result = new NotFoundResult();
                return;
            }

            resource = await resolver.ResolveAsync(_resourceType, rawId.ToString()!, context.HttpContext.RequestAborted);
            if (resource == null)
            {
                // Fail-closed: Resolver returned null (resource does not exist or unauthorized)
                context.Result = new NotFoundResult();
                return;
            }
        }
        else
        {
            // Non-ID operation (e.g. creation or batch operations): Find resource directly in action arguments (e.g. model bound entity or DTO)
            resource = context.ActionArguments.Values
                .FirstOrDefault(v => v != null && _resourceType.IsInstanceOfType(v));
        }

        // Fail-closed: If resource could not be resolved from arguments or resolver, deny with 404
        if (resource == null)
        {
            context.Result = new NotFoundResult();
            return;
        }

        // Authorize caller against resolved resource strictly before executing action
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
}
