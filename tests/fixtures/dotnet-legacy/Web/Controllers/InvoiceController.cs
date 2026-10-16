using System.Linq;
using System.Web.Mvc;

namespace Web.Controllers
{
    [Authorize]
    public class InvoiceController : Controller
    {
        private ShopDb db = new ShopDb();

        public ActionResult Details(int id)
        {
            var inv = db.Invoices.Find(id); // LSA-EXPECT:BOLA
            return View(inv);
        }

        public ActionResult Mine(int id)
        {
            var uid = CurrentUserId();
            var inv = db.Invoices.FirstOrDefault(i => i.Id == id && i.UserId == uid); // LSA-EXPECT:SAFE-BOLA
            if (inv == null) return HttpNotFound();
            return View(inv);
        }

        [HttpPost]
        public ActionResult Search(string customer)
        {
            var list = db.Database.SqlQuery<Invoice>("SELECT * FROM Invoices WHERE Customer = '" + customer + "'").ToList(); // LSA-EXPECT:SQLI LSA-EXPECT:BOLA
            return View(list);
        }
    }
}
