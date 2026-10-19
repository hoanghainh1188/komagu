package dev.komainu.legacy.shim;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Komainu Legacy Remediation Shim for Java (Servlet / JSP / Struts 1 / JDBC).
 *
 * <p>Drop-in, zero-dependency helper class to remediate BOLA/IDOR (CWE-639) and
 * SQL Injection (CWE-89) in legacy Java web applications that cannot yet migrate
 * to Spring Boot 3 (`remediate/authz` and `remediate/query`).
 *
 * <p>Security invariants enforced:
 * <ul>
 *   <li>Identity is strictly read from the server-side session or principal.</li>
 *   <li>Identifiers are normalized to canonical positive decimal numbers; empty, 0, negative and non-canonical IDs fail closed.</li>
 *   <li>Table and column identifiers are verified against an exact-match allow-list.</li>
 *   <li>Resource and owner keys are bound via JDBC {@link PreparedStatement}.</li>
 *   <li>Unauthorized access or missing identifiers throw {@link ResourceNotFoundOrForbiddenException} (mapped to HTTP 404).</li>
 * </ul>
 */
public final class OwnershipEnforcer {

    private static final Pattern SAFE_IDENTIFIER = Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]*$");
    private static final Pattern CANONICAL_POSITIVE_INT = Pattern.compile("^[1-9][0-9]{0,18}$");

    private OwnershipEnforcer() {
        // Utility class
    }

    /**
     * Schema descriptor for an allow-listed table's primary key and owner column.
     */
    public static final class TableOwnershipSchema {
        private final String tableName;
        private final String pkColumn;
        private final String ownerColumn;

        public TableOwnershipSchema(String tableName, String pkColumn, String ownerColumn) {
            this.tableName = validateFormat(tableName);
            this.pkColumn = validateFormat(pkColumn);
            this.ownerColumn = validateFormat(ownerColumn);
        }

        public String getTableName() {
            return tableName;
        }

        public String getPkColumn() {
            return pkColumn;
        }

        public String getOwnerColumn() {
            return ownerColumn;
        }
    }

    /**
     * Exception thrown when a resource does not exist, identifier is missing, or does not belong to the session user.
     * Callers in Servlet/Struts actions should catch this and return HTTP 404 Not Found.
     */
    public static final class ResourceNotFoundOrForbiddenException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public ResourceNotFoundOrForbiddenException(String message) {
            super(message);
        }
    }

    private static String validateFormat(String identifier) {
        Objects.requireNonNull(identifier, "Identifier must not be null");
        if (!SAFE_IDENTIFIER.matcher(identifier).matches()) {
            throw new IllegalArgumentException("Invalid SQL identifier format: " + identifier);
        }
        return identifier;
    }

    /**
     * Validate that an identifier is present in the provided exact-match allow-list.
     */
    public static String validateIdentifier(String identifier, Set<String> allowList) {
        Objects.requireNonNull(allowList, "Allow-list must not be null");
        if (!allowList.contains(identifier)) {
            throw new IllegalArgumentException("Disallowed SQL identifier: " + identifier);
        }
        return validateFormat(identifier);
    }

    /**
     * Validate and normalize a candidate identifier to a positive 64-bit integer.
     * Rejects null, empty strings, 0, negative values, hex/floating/scientific formats, and overflow.
     *
     * @param id Candidate identifier (String, Number, etc.)
     * @return Normalized positive long value
     * @throws IllegalArgumentException If identifier is null, empty, 0, negative, or non-canonical
     */
    public static long normalizeId(Object id) {
        if (id == null) {
            throw new IllegalArgumentException("Identifier must not be null.");
        }
        String s = id.toString().trim();
        if (s.isEmpty()) {
            throw new IllegalArgumentException("Identifier must not be empty.");
        }
        if (!CANONICAL_POSITIVE_INT.matcher(s).matches()) {
            throw new IllegalArgumentException("Identifier must be a positive canonical decimal integer: " + id);
        }
        try {
            long val = Long.parseLong(s);
            if (val <= 0) {
                throw new IllegalArgumentException("Identifier must be positive: " + id);
            }
            return val;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Identifier numeric overflow: " + id, e);
        }
    }

    /**
     * Verify two-way ownership between a target resource ID and the authenticated session user ID.
     *
     * @param conn          Active JDBC connection
     * @param table         Target table name
     * @param resourceId    Target resource ID from HTTP request
     * @param sessionUserId Authenticated user ID from server-side HttpSession
     * @param registry      Map of allow-listed table schemas
     * @return true if the row exists and belongs to {@code sessionUserId}, false otherwise
     * @throws SQLException On database errors
     */
    public static boolean checkOwnership(
            Connection conn,
            String table,
            Object resourceId,
            Object sessionUserId,
            Map<String, TableOwnershipSchema> registry) throws SQLException {
        Objects.requireNonNull(conn, "Connection must not be null");
        Objects.requireNonNull(registry, "Schema registry must not be null");

        long validResourceId;
        long validSessionUserId;
        try {
            validResourceId = normalizeId(resourceId);
            validSessionUserId = normalizeId(sessionUserId);
        } catch (IllegalArgumentException e) {
            // Empty, 0, negative, or non-canonical IDs fail closed immediately
            return false;
        }

        TableOwnershipSchema schema = registry.get(table);
        if (schema == null) {
            throw new IllegalArgumentException("Table is not registered in ownership allow-list: " + table);
        }

        String sql = String.format(
                "SELECT 1 FROM %s WHERE %s = ? AND %s = ?",
                schema.getTableName(),
                schema.getPkColumn(),
                schema.getOwnerColumn());

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, validResourceId);
            ps.setLong(2, validSessionUserId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Enforce two-way ownership or throw {@link ResourceNotFoundOrForbiddenException} (HTTP 404).
     *
     * @return Normalized positive long resourceId for caller to safely use
     */
    public static long requireOwnership(
            Connection conn,
            String table,
            Object resourceId,
            Object sessionUserId,
            Map<String, TableOwnershipSchema> registry) throws SQLException {
        long validResourceId;
        long validSessionUserId;
        try {
            validResourceId = normalizeId(resourceId);
            validSessionUserId = normalizeId(sessionUserId);
        } catch (IllegalArgumentException e) {
            throw new ResourceNotFoundOrForbiddenException("Invalid resource or user identifier (HTTP 404)");
        }

        TableOwnershipSchema schema = registry.get(table);
        if (schema == null) {
            throw new ResourceNotFoundOrForbiddenException("Resource not found or access denied (HTTP 404)");
        }

        if (!checkOwnership(conn, table, validResourceId, validSessionUserId, registry)) {
            throw new ResourceNotFoundOrForbiddenException("Resource not found or access denied (HTTP 404)");
        }

        return validResourceId;
    }

    /**
     * Sanitize a dynamic ORDER BY column and direction against an exact-match allow-list.
     *
     * @param inputColumn    User-supplied sort column (e.g., request.getParameter("sort"))
     * @param allowedColumns Set of permitted column names
     * @param defaultColumn  Fallback column if input is null or not in allow-list
     * @param inputDir       User-supplied direction ("ASC" or "DESC")
     * @return Safe "column ASC|DESC" SQL fragment
     */
    public static String safeOrderBy(
            String inputColumn,
            Set<String> allowedColumns,
            String defaultColumn,
            String inputDir) {
        Set<String> safeSet = new HashSet<>(Objects.requireNonNull(allowedColumns));
        String validatedDefault = validateIdentifier(defaultColumn, safeSet);
        String chosenColumn = (inputColumn != null && safeSet.contains(inputColumn))
                ? validateIdentifier(inputColumn, safeSet)
                : validatedDefault;
        String dir = "DESC".equalsIgnoreCase(inputDir) ? "DESC" : "ASC";
        return chosenColumn + " " + dir;
    }
}
