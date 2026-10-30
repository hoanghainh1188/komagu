package io.komagu.security.query

/**
 * Strict allow-list validator for dynamic query sorting in Spring Boot / Kotlin applications.
 * Prevents SQL/JPQL injection through user-supplied sort parameters.
 */
class SafeSortAllowList(allowedColumns: Collection<String>) {

    private val safeIdentifierRegex = Regex("^[a-zA-Z_][a-zA-Z0-9_]*$")
    private val allowedMap: Map<String, String>

    init {
        require(allowedColumns.isNotEmpty()) { "Allowed columns collection cannot be empty" }
        for (col in allowedColumns) {
            require(col.isNotBlank() && safeIdentifierRegex.matches(col)) {
                "Invalid column identifier in allow-list: '$col'. Must match ^[a-zA-Z_][a-zA-Z0-9_]*$"
            }
        }
        allowedMap = allowedColumns.associateBy { it.lowercase() }
    }

    /**
     * Validates that the requested column name strictly conforms to identifier syntax and exists in the allow-list.
     * Returns the canonical column name from the allow-list.
     * Throws SecurityException on validation failure.
     */
    fun validateColumnName(columnName: String?): String {
        if (columnName.isNullOrBlank()) {
            throw SecurityException("Sort column name cannot be null or blank")
        }

        val trimmed = columnName.trim()

        if (!safeIdentifierRegex.matches(trimmed)) {
            throw SecurityException("Potential SQL injection detected in sort column: '$columnName'. Illegal characters detected.")
        }

        return allowedMap[trimmed.lowercase()]
            ?: throw SecurityException("Unauthorized sort column requested: '$columnName'. Column is not in allowed list.")
    }

    /**
     * Builds a safe ORDER BY sort clause (e.g. "created_at ASC").
     */
    fun buildSortClause(columnName: String?, direction: String = "ASC"): String {
        val validColumn = validateColumnName(columnName)
        val dir = if (direction.trim().equals("DESC", ignoreCase = true)) "DESC" else "ASC"
        return "$validColumn $dir"
    }
}
