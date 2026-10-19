<!---
  Komainu Legacy Remediation Shim for ColdFusion (CFML)

  Fixes:
  1. CWE-287 / P12: Uses access="public" (NEVER access="remote" on data-access CFCs).
  2. CWE-89: Wraps all dynamic values in <cfqueryparam> with explicit cfsqltype.
  3. CWE-639: Enforces two-way binding between target resourceId and session.userId,
     returning HTTP 404 + <cfabort> on mismatch or invalid/missing identifiers.
  4. Falsy / 0 IDs: Rejects empty, 0, negative, and non-canonical IDs.
--->
<cfcomponent displayname="KomainuSecurityShim" output="false">

  <!---
    Validate and normalize a positive canonical decimal integer ID.
    Rejects 0, negative, empty, non-numeric, decimal, hex, or non-canonical strings.
  --->
  <cffunction name="normalizeId" access="public" returntype="string" output="false">
    <cfargument name="idValue" type="any" required="true">

    <cfif isNull(arguments.idValue)>
      <cfthrow type="Komainu.InvalidId" message="Identifier cannot be null.">
    </cfif>

    <cfset var s = trim(toString(arguments.idValue))>
    <cfif len(s) EQ 0 OR NOT reFind("^[1-9][0-9]{0,18}$", s)>
      <cfthrow type="Komainu.InvalidId" message="Identifier must be a positive canonical decimal integer.">
    </cfif>

    <cfreturn s>
  </cffunction>

  <!---
    Require an authenticated user ID from the server-side session scope.
    Rejects missing, empty, 0, negative, and non-canonical user IDs.
  --->
  <cffunction name="requireLogin" access="public" returntype="string" output="false">
    <cfif NOT structKeyExists(session, "userId")>
      <cfheader statuscode="401" statustext="Unauthorized">
      <cfoutput>401 Unauthorized</cfoutput>
      <cfabort>
    </cfif>

    <cftry>
      <cfset var normUid = normalizeId(session.userId)>
      <cfreturn normUid>
      <cfcatch type="any">
        <cfheader statuscode="401" statustext="Unauthorized">
        <cfoutput>401 Unauthorized</cfoutput>
        <cfabort>
      </cfcatch>
    </cftry>
  </cffunction>

  <!---
    Validate that an identifier is in the exact-match allow-list.
  --->
  <cffunction name="validateIdentifier" access="public" returntype="string" output="false">
    <cfargument name="identifier" type="string" required="true">
    <cfargument name="allowList" type="array" required="true">

    <cfif NOT arrayFind(arguments.allowList, arguments.identifier)>
      <cfthrow type="Komainu.DisallowedIdentifier" message="Disallowed SQL identifier.">
    </cfif>
    <cfif NOT reFind("^[a-zA-Z_][a-zA-Z0-9_]*$", arguments.identifier)>
      <cfthrow type="Komainu.InvalidIdentifier" message="Invalid SQL identifier format.">
    </cfif>
    <cfreturn arguments.identifier>
  </cffunction>

  <!---
    Enforce two-way ownership on a target record or abort with HTTP 404 Not Found.
    Traps all errors locally (invalid identifiers, database errors, non-canonical IDs)
    and consistently emits HTTP 404.
    Returns the normalized resourceId for the caller to safely use.
  --->
  <cffunction name="enforceOwnership" access="public" returntype="string" output="false">
    <cfargument name="datasource" type="string" required="true">
    <cfargument name="table" type="string" required="true">
    <cfargument name="pkColumn" type="string" required="true">
    <cfargument name="resourceId" type="any" required="true">
    <cfargument name="ownerColumn" type="string" required="true">
    <cfargument name="sessionUserId" type="any" required="true">
    <cfargument name="allowedTables" type="array" required="true">
    <cfargument name="allowedColumns" type="array" required="true">

    <cftry>
      <cfset var safeTable = validateIdentifier(arguments.table, arguments.allowedTables)>
      <cfset var safePk = validateIdentifier(arguments.pkColumn, arguments.allowedColumns)>
      <cfset var safeOwner = validateIdentifier(arguments.ownerColumn, arguments.allowedColumns)>
      <cfset var normResId = normalizeId(arguments.resourceId)>
      <cfset var normUid = normalizeId(arguments.sessionUserId)>
      <cfset var qOwnership = "">

      <cfquery name="qOwnership" datasource="#arguments.datasource#">
        SELECT 1 AS is_owner
        FROM #safeTable#
        WHERE #safePk# = <cfqueryparam value="#normResId#" cfsqltype="cf_sql_bigint">
          AND #safeOwner# = <cfqueryparam value="#normUid#" cfsqltype="cf_sql_bigint">
      </cfquery>

      <cfif qOwnership.recordCount EQ 0>
        <cfthrow type="Komainu.AccessDenied" message="Record not found or not owned.">
      </cfif>

      <cfreturn normResId>

      <cfcatch type="any">
        <cfheader statuscode="404" statustext="Not Found">
        <cfoutput>404 Not Found</cfoutput>
        <cfabort>
      </cfcatch>
    </cftry>
  </cffunction>

  <!---
    Sanitize dynamic ORDER BY column against an exact-match allow-list.
  --->
  <cffunction name="safeOrderBy" access="public" returntype="string" output="false">
    <cfargument name="inputColumn" type="string" required="false" default="">
    <cfargument name="allowedColumns" type="array" required="true">
    <cfargument name="defaultColumn" type="string" required="true">
    <cfargument name="inputDir" type="string" required="false" default="ASC">

    <cfset var safeDefault = validateIdentifier(arguments.defaultColumn, arguments.allowedColumns)>
    <cfset var chosen = safeDefault>
    <cfset var dir = "ASC">

    <cfif len(arguments.inputColumn) GT 0 AND arrayFind(arguments.allowedColumns, arguments.inputColumn)>
      <cfset chosen = validateIdentifier(arguments.inputColumn, arguments.allowedColumns)>
    </cfif>
    <cfif uCase(arguments.inputDir) EQ "DESC">
      <cfset dir = "DESC">
    </cfif>

    <cfreturn chosen & " " & dir>
  </cffunction>

</cfcomponent>
