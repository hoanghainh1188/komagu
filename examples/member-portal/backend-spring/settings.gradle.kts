rootProject.name = "member-portal-backend-spring"

includeBuild("../../../remediate/authz/spring") {
    name = "authz-spring"
}
includeBuild("../../../remediate/identity/spring") {
    name = "identity-spring"
}
includeBuild("../../../remediate/query/spring") {
    name = "query-spring"
}
