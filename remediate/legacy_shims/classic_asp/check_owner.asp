<%
' =============================================================================
' Komagu Legacy Remediation Shim for Classic ASP (VBScript)
'
' Include this file in legacy ASP endpoints:
'   <!--#include file="../inc/check_owner.asp"-->
'
' Fixes:
' 1. BOLA / P13 (CWE-639): Enforces two-way ownership binding between
'    Session("UserID") and target resource IDs (member_id, order_id, cart_id).
' 2. Check-Without-Stop / P4: Emits HTTP 404 Not Found and calls Response.End
'    immediately on mismatch or error.
' 3. Error Trapping: Traps errors locally with On Error Resume Next and emits
'    404 instead of raising unhandled exceptions (preventing bypass when caller
'    uses On Error Resume Next).
' 4. Canonical ID Validation: Rejects empty, 0, negative, and non-canonical IDs.
' 5. SQL Injection (CWE-89): Uses ADODB.Command with bound Parameters (?)
'    instead of string concatenation.
' =============================================================================

Const adInteger = 3
Const adParamInput = 1
Const adCmdText = 1

' Halt execution with HTTP 401 Unauthorized
Sub KomaguHalt401()
    Response.Clear
    Response.Status = "401 Unauthorized"
    Response.Write "401 Unauthorized"
    Response.End
End Sub

' Halt execution with HTTP 404 Not Found
Sub KomaguHalt404()
    Response.Clear
    Response.Status = "404 Not Found"
    Response.Write "404 Not Found"
    Response.End
End Sub

' Validate and normalize a positive canonical integer ID
' Rejects null, empty, 0, negative, hex (&H), scientific (1e2), decimals, and overflow
Function KomaguNormalizeId(idVal)
    KomaguNormalizeId = 0
    If IsNull(idVal) Or IsEmpty(idVal) Then Exit Function

    Dim s, i, ch
    s = Trim(CStr(idVal))
    If Len(s) = 0 Or Len(s) > 10 Then Exit Function

    ' First character must be 1-9 (reject 0, 007, negative, plus sign)
    ch = Left(s, 1)
    If Asc(ch) < Asc("1") Or Asc(ch) > Asc("9") Then Exit Function

    ' All subsequent characters must be 0-9
    For i = 2 To Len(s)
        ch = Mid(s, i, 1)
        If Asc(ch) < Asc("0") Or Asc(ch) > Asc("9") Then Exit Function
    Next

    ' Protect against 32-bit signed long overflow (> 2,147,483,647)
    If CDbl(s) > 2147483647 Then Exit Function

    KomaguNormalizeId = CLng(s)
End Function

' Require an authenticated numeric UserID in Session("UserID")
Function KomaguRequireLogin()
    On Error Resume Next
    Dim normUid
    normUid = KomaguNormalizeId(Session("UserID"))
    If normUid <= 0 Or Err.Number <> 0 Then
        KomaguHalt401
    End If
    KomaguRequireLogin = normUid
End Function

' Exact-match allow-list check against a comma-separated list of safe identifiers
Function KomaguIsAllowedIdentifier(candidate, allowedCsv)
    KomaguIsAllowedIdentifier = False
    If IsNull(candidate) Or IsEmpty(candidate) Then Exit Function
    Dim items, item
    items = Split(allowedCsv, ",")
    For Each item In items
        If Trim(item) = CStr(candidate) Then
            KomaguIsAllowedIdentifier = True
            Exit Function
        End If
    Next
End Function

' Verify two-way ownership using parameterized ADODB.Command; halt with 404 on mismatch or error
' Returns normalized resourceId for the caller to safely use
Function KomaguEnforceOwnership(conn, tableName, pkCol, resourceId, ownerCol, sessionUserId, allowedTablesCsv, allowedColsCsv)
    On Error Resume Next

    ' Fail closed on invalid table or column identifiers (avoid raising unhandled errors to prevent bypass under caller error handlers)
    If Not KomaguIsAllowedIdentifier(tableName, allowedTablesCsv) Then
        KomaguHalt404
    End If
    If Not KomaguIsAllowedIdentifier(pkCol, allowedColsCsv) Or Not KomaguIsAllowedIdentifier(ownerCol, allowedColsCsv) Then
        KomaguHalt404
    End If

    ' Strictly validate and normalize both identifiers
    Dim normResId, normUid
    normResId = KomaguNormalizeId(resourceId)
    normUid = KomaguNormalizeId(sessionUserId)
    If normResId <= 0 Or normUid <= 0 Or Err.Number <> 0 Then
        KomaguHalt404
    End If

    Dim cmd, rs, sql, isOwner
    sql = "SELECT 1 FROM " & tableName & " WHERE " & pkCol & " = ? AND " & ownerCol & " = ?"

    Set cmd = Server.CreateObject("ADODB.Command")
    If Err.Number <> 0 Or cmd Is Nothing Then
        KomaguHalt404
    End If

    Set cmd.ActiveConnection = conn
    cmd.CommandText = sql
    cmd.CommandType = adCmdText
    cmd.Parameters.Append cmd.CreateParameter("@p_id", adInteger, adParamInput, , normResId)
    cmd.Parameters.Append cmd.CreateParameter("@p_uid", adInteger, adParamInput, , normUid)

    Set rs = cmd.Execute()
    If Err.Number <> 0 Or rs Is Nothing Then
        KomaguHalt404
    End If

    isOwner = Not rs.EOF
    rs.Close
    Set rs = Nothing
    Set cmd = Nothing

    If Err.Number <> 0 Or Not isOwner Then
        KomaguHalt404
    End If

    KomaguEnforceOwnership = normResId
End Function

' Safe ORDER BY helper using an exact-match allow-list
Function KomaguSafeOrderBy(inputCol, allowedColsCsv, defaultCol, inputDir)
    Dim chosen, dir
    chosen = defaultCol
    If KomaguIsAllowedIdentifier(inputCol, allowedColsCsv) Then
        chosen = inputCol
    End If
    If UCase(CStr(inputDir)) = "DESC" Then
        dir = "DESC"
    Else
        dir = "ASC"
    End If
    KomaguSafeOrderBy = chosen & " " & dir
End Function
%>
