<cfcomponent>
  <cffunction name="getOrder" access="remote" returnformat="json">
    <cfargument name="orderId" type="string" required="true">
    <cfquery name="q" datasource="shop">
      SELECT * FROM orders WHERE id = #arguments.orderId# <!--- LSA-EXPECT:SQLI LSA-EXPECT:BOLA --->
    </cfquery>
    <cfreturn q>
  </cffunction>
  <cffunction name="internalHelper" access="private">
    <cfreturn 1>
  </cffunction>
</cfcomponent>
