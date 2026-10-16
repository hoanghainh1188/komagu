Imports System.Data.SqlClient

Partial Class EditOrder
    Inherits BasePage

    Protected Sub btnSave_Click(sender As Object, e As EventArgs) Handles btnSave.Click
        Dim sql As String = "UPDATE Orders SET Note = '" & txtNote.Text & "'" ' LSA-EXPECT:SQLI
        sql &= " WHERE OrderId = " & hfOrderId.Value ' LSA-EXPECT:SQLI LSA-EXPECT:BOLA
        Using conn As New SqlConnection(ConnStr)
            Dim cmd As New SqlCommand(sql, conn)
            conn.Open()
            cmd.ExecuteNonQuery()
        End Using
        Response.Redirect("OrderList.aspx", False)
    End Sub
End Class
