<%
' =============================================================================
' Komainu Legacy Remediation Shim for Classic ASP (VBScript)
'
' Include this file in legacy ASP endpoints:
'   <!--#include file="../inc/check_owner.asp"-->
'
' Fixes:
' 1. BOLA / P13 (CWE-639): Enforces two-way ownership binding between
'    Session("UserID") and target resource IDs (member_id, order_id, cart_id).
' 2. Check-Without-Stop / P4: Emits HTTP 404 Not Found and calls Response.End
'    immediately on mismatch.
' 3. SQL Injection (CWE-89): Uses ADODB.Command with bound Parameters (?)
'    instead of string concatenation (`conn.Execute "DELETE ... " & Request(...)`).
' =============================================================================

Const adInteger = 3
Const adParamInput = 1
Const adCmdText = 1

' Require an authenticated numeric UserID in Session("UserID")
Function KomainuRequireLogin()
    If IsEmpty(Session("UserID")) Or IsNull(Session("UserID")) Or Not IsNumeric(Session("UserID")) Then
        Response.Status = "401 Unauthorized"
        Response.Write "401 Unauthorized"
        Response.End
    End If
    KomainuRequireLogin = CLng(Session("UserID"))
End Function

' Exact-match allow-list check against a comma-separated list of safe identifiers
Function KomainuIsAllowedIdentifier(candidate, allowedCsv)
    KomainuIsAllowedIdentifier = False
    If IsNull(candidate) Or IsEmpty(candidate) Then Exit Function
    Dim items, item
    items = Split(allowedCsv, ",")
    For Each item In items
        If Trim(item) = CStr(candidate) Then
            KomainuIsAllowedIdentifier = True
            Exit Function
        End If
    Next
End Function

' Verify two-way ownership using parameterized ADODB.Command; halt with 404 on mismatch
Sub KomainuEnforceOwnership(conn, tableName, pkCol, resourceId, ownerCol, sessionUserId, allowedTablesCsv, allowedColsCsv)
    If Not KomainuIsAllowedIdentifier(tableName, allowedTablesCsv) Then
        Err.Raise vbObjectError + 1001, "KomainuShim", "Disallowed table identifier"
    End If
    If Not KomainuIsAllowedIdentifier(pkCol, allowedColsCsv) Or Not KomainuIsAllowedIdentifier(ownerCol, allowedColsCsv) Then
        Err.Raise vbObjectError + 1002, "KomainuShim", "Disallowed column identifier"
    End If

    If Not IsNumeric(resourceId) Or Not IsNumeric(sessionUserId) Then
        Response.Status = "404 Not Found"
        Response.Write "404 Not Found"
        Response.End
    End If

    Dim cmd, rs, sql, isOwner
    sql = "SELECT 1 FROM " & tableName & " WHERE " & pkCol & " = ? AND " & ownerCol & " = ?"

    Set cmd = Server.CreateObject("ADODB.Command")
    Set cmd.ActiveConnection = conn
    cmd.CommandText = sql
    cmd.CommandType = adCmdText
    cmd.Parameters.Append cmd.CreateParameter("@p_id", adInteger, adParamInput, , CLng(resourceId))
    cmd.Parameters.Append cmd.CreateParameter("@p_uid", adInteger, adParamInput, , CLng(sessionUserId))

    Set rs = cmd.Execute()
    isOwner = Not rs.EOF
    rs.Close
    Set rs = Nothing
    Set cmd = Nothing

    If Not isOwner Then
        Response.Status = "404 Not Found"
        Response.Write "404 Not Found"
        Response.End
    End If
End Sub

' Safe ORDER BY helper using an exact-match allow-list
Function KomainuSafeOrderBy(inputCol, allowedColsCsv, defaultCol, inputDir)
    Dim chosen, dir
    chosen = defaultCol
    If KomainuIsAllowedIdentifier(inputCol, allowedColsCsv) Then
        chosen = inputCol
    End If
    If UCase(CStr(inputDir)) = "DESC" Then
        dir = "DESC"
    Else
        dir = "ASC"
    End If
    KomainuSafeOrderBy = chosen & " " & dir
End Function
%>
