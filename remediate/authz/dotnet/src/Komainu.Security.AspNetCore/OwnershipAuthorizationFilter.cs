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

        // Try to find resource directly in action arguments (e.g. model bound entity or DTO)
        object? resource = context.ActionArguments.Values
            .FirstOrDefault(v => v != null && _resourceType.IsInstanceOfType(v));

        if (resource == null)
        {
            // Try resolving via route parameter ID and registered IKomainuResourceResolver
            if (context.RouteData.Values.TryGetValue(_idRouteParameter, out var rawId) && rawId != null)
            {
                var resolver = context.HttpContext.RequestServices.GetService<IKomainuResourceResolver>();
                if (resolver != null)
                {
                    resource = await resolver.ResolveAsync(_resourceType, rawId.ToString()!, context.HttpContext.RequestAborted);
                }
            }
        }

        if (resource != null)
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
                var authResult = await _authorizationService.AuthorizeAsync(
                    user,
                    objectResult.Value,
                    _operation,
                    context.HttpContext.RequestAborted);

                if (!authResult.Succeeded)
                {
                    // Intercept and rewrite response to 404 Not Found
                    executedContext.Result = new NotFoundResult();
                }
            }
        }
    }
}
