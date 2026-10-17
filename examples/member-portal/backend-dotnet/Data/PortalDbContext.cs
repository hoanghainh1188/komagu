namespace MemberPortal.Backend.Data;

using MemberPortal.Backend.Models;
using Microsoft.EntityFrameworkCore;

public class PortalDbContext : DbContext
{
    public PortalDbContext(DbContextOptions<PortalDbContext> options) : base(options)
    {
    }

    public DbSet<Order> Orders => Set<Order>();
    public DbSet<Document> Documents => Set<Document>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Order>(b =>
        {
            b.HasKey(o => o.Id);
            b.Property(o => o.TotalAmount).HasColumnType("TEXT");
        });

        modelBuilder.Entity<Document>(b =>
        {
            b.HasKey(d => d.Id);
        });

        // Seed initial reference data matching the threat model in ADR-0004
        modelBuilder.Entity<Order>().HasData(
            new Order
            {
                Id = "ord-001",
                TenantId = "tenant-alpha",
                OwnerUserId = "user-a",
                TotalAmount = 1250.00m,
                Status = "completed",
                Description = "Q3 Dedicated Cloud Cluster Payment",
                CreatedAt = new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc)
            },
            new Order
            {
                Id = "ord-002",
                TenantId = "tenant-alpha",
                OwnerUserId = "user-a",
                TotalAmount = 450.00m,
                Status = "pending",
                Description = "Annual Developer Tooling Licenses",
                CreatedAt = new DateTime(2026, 10, 5, 0, 0, 0, DateTimeKind.Utc)
            },
            new Order
            {
                Id = "ord-003",
                TenantId = "tenant-alpha",
                OwnerUserId = "user-b",
                TotalAmount = 89.00m,
                Status = "completed",
                Description = "VPN Gateway Extension",
                CreatedAt = new DateTime(2026, 10, 10, 0, 0, 0, DateTimeKind.Utc)
            },
            new Order
            {
                Id = "ord-004",
                TenantId = "tenant-beta",
                OwnerUserId = "user-c",
                TotalAmount = 5000.00m,
                Status = "completed",
                Description = "Strategic Security Architecture Audit",
                CreatedAt = new DateTime(2026, 10, 12, 0, 0, 0, DateTimeKind.Utc)
            }
        );

        modelBuilder.Entity<Document>().HasData(
            new Document
            {
                Id = "doc-001",
                TenantId = "tenant-alpha",
                OwnerUserId = "user-a",
                Title = "Tenant Alpha Q3 Financial Summary",
                Content = "CONFIDENTIAL: Alpha Corp financial balance and quarterly EBITDA.",
                IsConfidential = true,
                CreatedAt = new DateTime(2026, 10, 2, 0, 0, 0, DateTimeKind.Utc)
            },
            new Document
            {
                Id = "doc-002",
                TenantId = "tenant-beta",
                OwnerUserId = "user-c",
                Title = "Beta Corp Merger & Acquisition Term Sheet",
                Content = "STRICTLY PRIVATE: Merger terms between Beta Holdings and Acquirer.",
                IsConfidential = true,
                CreatedAt = new DateTime(2026, 10, 14, 0, 0, 0, DateTimeKind.Utc)
            }
        );
    }
}
