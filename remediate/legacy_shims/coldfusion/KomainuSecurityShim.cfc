<!---
  Komainu Legacy Remediation Shim for ColdFusion (CFML)

  Fixes:
  1. CWE-287 / P12: Uses access="public" (NEVER access="remote" on data-access CFCs).
  2. CWE-89: Wraps all dynamic values in <cfqueryparam> with explicit cfsqltype.
  3. CWE-639: Enforces two-way binding between target resourceId and session.userId,
     returning HTTP 404 + <cfabort> on mismatch.
--->
<cfcomponent displayname="KomainuSecurityShim" output="false">

  <!---
    Require an authenticated user ID from the server-side session scope.
  --->
  <cffunction name="requireLogin" access="public" returntype="any" output="false">
    <cfif NOT structKeyExists(session, "userId") OR len(trim(session.userId)) EQ 0>
      <cfheader statuscode="401" statustext="Unauthorized">
      <cfoutput>401 Unauthorized</cfoutput>
      <cfabort>
    </cfif>
    <cfreturn session.userId>
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
  --->
  <cffunction name="enforceOwnership" access="public" returntype="void" output="false">
    <cfargument name="datasource" type="string" required="true">
    <cfargument name="table" type="string" required="true">
    <cfargument name="pkColumn" type="string" required="true">
    <cfargument name="resourceId" type="numeric" required="true">
    <cfargument name="ownerColumn" type="string" required="true">
    <cfargument name="sessionUserId" type="numeric" required="true">
    <cfargument name="allowedTables" type="array" required="true">
    <cfargument name="allowedColumns" type="array" required="true">

    <cfset var safeTable = validateIdentifier(arguments.table, arguments.allowedTables)>
    <cfset var safePk = validateIdentifier(arguments.pkColumn, arguments.allowedColumns)>
    <cfset var safeOwner = validateIdentifier(arguments.ownerColumn, arguments.allowedColumns)>
    <cfset var qOwnership = "">

    <cfquery name="qOwnership" datasource="#arguments.datasource#">
      SELECT 1 AS is_owner
      FROM #safeTable#
      WHERE #safePk# = <cfqueryparam value="#arguments.resourceId#" cfsqltype="cf_sql_integer">
        AND #safeOwner# = <cfqueryparam value="#arguments.sessionUserId#" cfsqltype="cf_sql_integer">
    </cfquery>

    <cfif qOwnership.recordCount EQ 0>
      <cfheader statuscode="404" statustext="Not Found">
      <cfoutput>404 Not Found</cfoutput>
      <cfabort>
    </cfif>
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
