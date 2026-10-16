using System;
using System.Data.SqlClient;

namespace Web.Orders
{
    public partial class OrderDetail : BasePage
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string id = Request.QueryString["id"];
            using (var conn = new SqlConnection(ConnStr))
            {
                var cmd = new SqlCommand("SELECT * FROM Orders WHERE OrderId = " + id, conn); // LSA-EXPECT:SQLI LSA-EXPECT:BOLA
                conn.Open();
                var r = cmd.ExecuteReader();
                var safe = new SqlCommand("SELECT * FROM Orders WHERE OrderId = @id AND UserId = @uid", conn); // LSA-EXPECT:SAFE-SQL-NOFLAG
                safe.Parameters.AddWithValue("@id", id);
                safe.Parameters.AddWithValue("@uid", Session["UserID"]);
                string sql2 = string.Format("SELECT * FROM Logs WHERE Ref = '{0}'", Request["ref"]); // LSA-EXPECT:SQLI
                string sql3 = $"DELETE FROM Carts WHERE CartId = {Request.Form["cart"]}"; // LSA-EXPECT:SQLI
                new SqlCommand(sql2, conn).ExecuteReader();
                new SqlCommand(sql3, conn).ExecuteNonQuery();
            }
        }
    }
}
