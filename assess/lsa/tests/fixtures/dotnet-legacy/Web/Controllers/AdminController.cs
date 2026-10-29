using System.Linq;
using System.Web.Mvc;

namespace Web.Controllers
{
    [Authorize]
    public class AdminController : Controller
    {
        private ShopDb db = new ShopDb();

        [HttpPost]
        public ActionResult DeleteUser(int id)
        {
            var u = db.Users.Find(id);
            db.Users.Remove(u); // LSA-EXPECT:BFLA
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public ActionResult ResetPassword(int id)
        {
            var u = db.Users.Find(id); // LSA-EXPECT:SAFE-BFLA
            u.MustResetPassword = true;
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        public ActionResult Export()
        {
            if (Request.QueryString["isAdmin"] == "true") // LSA-EXPECT:BFLA
            {
                return Json(db.Users.ToList(), JsonRequestBehavior.AllowGet);
            }
            return HttpNotFound();
        }
    }
}
