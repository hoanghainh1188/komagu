using System.Data.Entity;

namespace Web.Models
{
    public class ShopDb : DbContext
    {
        public DbSet<Customer> Customers { get; set; }
        public DbSet<Invoice> Invoices { get; set; }
    }
}
