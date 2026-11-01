namespace Komagu.Security.Authorization.Tests;

using System.Text.Json;
using Xunit;

/// <summary>
/// Mass-assignment remediation example: replace whole-entity binding (or <c>[Bind(Include = "...")]</c>) with a
/// request DTO that declares only the client-editable fields, then copy them onto the tracked entity explicitly.
/// </summary>
public class MassAssignmentDtoTests
{
    /// <summary>Persisted entity: Role, IsAdmin and Balance must never be client-writable.</summary>
    public sealed class Customer
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = "customer";
        public bool IsAdmin { get; set; }
        public decimal Balance { get; set; }
    }

    /// <summary>Allow-list DTO: only the fields a customer may edit on their own profile.</summary>
    public sealed record ProfileUpdateDto(string Name, string Email)
    {
        /// <summary>Explicit copy: privileged fields are not reachable from the request.</summary>
        public void ApplyTo(Customer customer)
        {
            ArgumentNullException.ThrowIfNull(customer);
            customer.Name = Name;
            customer.Email = Email;
        }
    }

    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public void ProfileUpdate_WithPrivilegedFieldsInJson_ChangesOnlyAllowListedFields()
    {
        var customer = new Customer { Id = 7, Name = "Old", Email = "old@example.com", Role = "customer", IsAdmin = false, Balance = 10m };
        const string attackerJson = """
            {"id": 1, "name": "New Name", "email": "new@example.com", "role": "admin", "isAdmin": true, "balance": 999999}
            """;

        var dto = JsonSerializer.Deserialize<ProfileUpdateDto>(attackerJson, WebJson);
        Assert.NotNull(dto);
        dto!.ApplyTo(customer);

        Assert.Equal("New Name", customer.Name);
        Assert.Equal("new@example.com", customer.Email);
        Assert.Equal(7, customer.Id);
        Assert.Equal("customer", customer.Role);
        Assert.False(customer.IsAdmin);
        Assert.Equal(10m, customer.Balance);
    }

    [Fact]
    public void ProfileUpdateDto_ExposesOnlyNameAndEmail()
    {
        var writable = typeof(ProfileUpdateDto).GetProperties().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal);
        Assert.Equal(new[] { "Email", "Name" }, writable);
    }

    [Fact]
    public void WholeEntityBinding_IsTheVulnerablePattern()
    {
        // Contrast: deserializing straight into the entity lets the client set Role/IsAdmin/Balance.
        const string attackerJson = """{"name": "x", "email": "x@example.com", "role": "admin", "isAdmin": true, "balance": 999999}""";

        var bound = JsonSerializer.Deserialize<Customer>(attackerJson, WebJson)!;

        Assert.Equal("admin", bound.Role);
        Assert.True(bound.IsAdmin);
        Assert.Equal(999999m, bound.Balance);
    }
}
