namespace MemberPortal.Backend.Models;

using System;
using Komainu.Security.Authorization;

/// <summary>
/// Domain entity representing a customer order, bound to a specific tenant and owner.
/// </summary>
public class Order : IOwnedResource<string>
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string TenantId { get; set; } = string.Empty;
    public string OwnerUserId { get; set; } = string.Empty;
    public decimal TotalAmount { get; set; }
    public string Status { get; set; } = "pending";
    public string Description { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Domain entity representing a confidential business document.
/// </summary>
public class Document : IOwnedResource<string>
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string TenantId { get; set; } = string.Empty;
    public string OwnerUserId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public bool IsConfidential { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// DTO representing an authenticated persona available in the switcher.
/// </summary>
public record PersonaDto(
    string UserId,
    string DisplayName,
    string TenantId,
    string TenantName,
    string Role,
    string MockToken
);
