namespace Komagu.Security.Authorization.Tests;

using Komagu.Security.Authorization;
using Komagu.Security.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Xunit;

public class ScopedQueryTests
{
    public class OrderEntity : IOwnedResource<Guid>, IOwnedResource
    {
        public Guid Id { get; set; }
        public string OwnerUserId { get; set; } = string.Empty;
        public string TenantId { get; set; } = string.Empty;
        public decimal TotalAmount { get; set; }
    }

    public class TestDbContext : DbContext
    {
        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }
        public DbSet<OrderEntity> Orders => Set<OrderEntity>();
    }

    [Fact]
    public async Task WithUserScope_FiltersOutCrossUserAndCrossTenantRecords()
    {
        // Arrange
        var options = new DbContextOptionsBuilder<TestDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        await using var context = new TestDbContext(options);

        // Seed 4 records:
        // 1. Target user, Target tenant (MATCH)
        // 2. Other user, Target tenant (BOLA attempt -> MUST BE FILTERED)
        // 3. Target user, Other tenant (Cross-tenant -> MUST BE FILTERED)
        // 4. Other user, Other tenant (MUST BE FILTERED)
        context.Orders.AddRange(
            new OrderEntity { Id = Guid.NewGuid(), OwnerUserId = "alice", TenantId = "tenant-1", TotalAmount = 100m },
            new OrderEntity { Id = Guid.NewGuid(), OwnerUserId = "bob", TenantId = "tenant-1", TotalAmount = 200m },
            new OrderEntity { Id = Guid.NewGuid(), OwnerUserId = "alice", TenantId = "tenant-2", TotalAmount = 300m },
            new OrderEntity { Id = Guid.NewGuid(), OwnerUserId = "charlie", TenantId = "tenant-2", TotalAmount = 400m }
        );
        await context.SaveChangesAsync();

        // Act: Scoped query for Alice in Tenant 1
        var visibleOrders = await context.Orders
            .WithUserScope<OrderEntity, Guid>("alice", "tenant-1")
            .ToListAsync();

        // Assert
        Assert.Single(visibleOrders);
        Assert.Equal(100m, visibleOrders[0].TotalAmount);
        Assert.Equal("alice", visibleOrders[0].OwnerUserId);
        Assert.Equal("tenant-1", visibleOrders[0].TenantId);
    }

    [Fact]
    public async Task WithTenantScope_FiltersOutCrossTenantRecords()
    {
        // Arrange
        var options = new DbContextOptionsBuilder<TestDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        await using var context = new TestDbContext(options);

        context.Orders.AddRange(
            new OrderEntity { Id = Guid.NewGuid(), OwnerUserId = "alice", TenantId = "tenant-1", TotalAmount = 100m },
            new OrderEntity { Id = Guid.NewGuid(), OwnerUserId = "bob", TenantId = "tenant-1", TotalAmount = 200m },
            new OrderEntity { Id = Guid.NewGuid(), OwnerUserId = "alice", TenantId = "tenant-2", TotalAmount = 300m }
        );
        await context.SaveChangesAsync();

        // Act
        var tenant1Orders = await context.Orders
            .WithTenantScope<OrderEntity>("tenant-1")
            .ToListAsync();

        // Assert
        Assert.Equal(2, tenant1Orders.Count);
        Assert.All(tenant1Orders, o => Assert.Equal("tenant-1", o.TenantId));
    }
}
