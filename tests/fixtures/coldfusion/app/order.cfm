<cfif NOT structKeyExists(session, "userID")><cflocation url="/login.cfm"></cfif>
<cfquery name="qOrder" datasource="shop">
  SELECT * FROM orders WHERE id = #url.id# <!--- LSA-EXPECT:SQLI LSA-EXPECT:BOLA --->
</cfquery>
<cfquery name="qMine" datasource="shop">
  SELECT * FROM orders
  WHERE id = <cfqueryparam value="#url.id#" cfsqltype="cf_sql_integer"> <!--- LSA-EXPECT:SAFE-SQL-NOFLAG --->
    AND user_id = <cfqueryparam value="#session.userID#" cfsqltype="cf_sql_integer">
</cfquery>
<cfoutput>#qOrder.address#</cfoutput>
