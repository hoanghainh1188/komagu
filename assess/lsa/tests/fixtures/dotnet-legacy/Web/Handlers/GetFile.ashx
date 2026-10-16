<%@ WebHandler Language="C#" Class="GetFile" %>
using System.Web;

public class GetFile : IHttpHandler
{
    public void ProcessRequest(HttpContext context)
    {
        string fileId = context.Request.QueryString["file_id"];
        string path = DocStore.PathFor(fileId);
        context.Response.TransmitFile(path); // LSA-EXPECT:BOLA
    }
    public bool IsReusable { get { return false; } }
}
