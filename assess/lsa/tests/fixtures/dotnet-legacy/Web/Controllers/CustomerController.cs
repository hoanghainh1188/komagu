using System.Web.Mvc;
using Web.Models;

namespace Web.Controllers
{
    [Authorize]
    public class CustomerController : Controller
    {
        private ShopDb db = new ShopDb();

        [HttpPost]
        public ActionResult Edit(Customer customer) // LSA-EXPECT:MASS
        {
            db.Entry(customer).State = System.Data.Entity.EntityState.Modified;
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        [HttpPost]
        public ActionResult EditName([Bind(Include = "Id,Name")] Customer customer) // LSA-EXPECT:SAFE-MASS
        {
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        [HttpPost]
        public ActionResult Refresh(int id)
        {
            var customer = db.Customers.Find(id);
            TryUpdateModel(customer); // LSA-EXPECT:MASS
            db.SaveChanges();
            return RedirectToAction("Index");
        }
    }
}
