<?php
/**
 * Komainu Legacy Remediation Shim for PHP (PDO)
 *
 * Drop-in helper functions to remediate BOLA/IDOR (CWE-639) and SQL Injection (CWE-89)
 * in legacy PHP applications (Plain PHP, CodeIgniter, legacy custom frameworks).
 *
 * Security invariants enforced:
 * 1. Identity is strictly read from server-side $_SESSION.
 * 2. Table and column identifiers are validated against an exact-match allow-list.
 * 3. Resource IDs and owner IDs are strictly normalized to canonical positive decimals.
 * 4. Resource IDs and owner IDs are bound using PDO prepared statements.
 * 5. SQL statements are fully portable across DBMSs (no non-standard LIMIT clauses).
 * 6. Mismatches and invalid/missing identifiers emit HTTP 404 Not Found and immediately call exit().
 */

declare(strict_types=1);

/**
 * Validate that an identifier (table or column name) is strictly in the allow-list
 * and matches safe alphanumeric/underscore syntax.
 *
 * @param string $identifier Candidate table or column name
 * @param array<int, string> $allowList Allowed identifier literals
 * @return string Validated identifier
 * @throws InvalidArgumentException If identifier is not in the allow-list or has invalid format
 */
function komainu_validate_identifier(string $identifier, array $allowList): string
{
    if (!in_array($identifier, $allowList, true)) {
        throw new InvalidArgumentException('Disallowed SQL identifier.');
    }
    if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $identifier)) {
        throw new InvalidArgumentException('Invalid SQL identifier format.');
    }
    return $identifier;
}

/**
 * Validate and normalize a canonical positive decimal integer identifier.
 * Rejects null, empty string, 0, '0', false, negative numbers, hex, scientific notation,
 * leading zeroes, and non-decimal characters.
 *
 * @param mixed $id Candidate resource or user identifier
 * @return int|string Normalized integer ID (int when <= PHP_INT_MAX, string digits otherwise)
 * @throws InvalidArgumentException If identifier is falsy, non-positive, or non-canonical
 */
function komainu_normalize_id($id)
{
    if ($id === null || $id === '' || $id === false || $id === true) {
        throw new InvalidArgumentException('Identifier cannot be empty, null, or boolean.');
    }

    if (is_int($id)) {
        if ($id <= 0) {
            throw new InvalidArgumentException('Identifier must be a positive integer.');
        }
        return $id;
    }

    if (!is_string($id) && !is_numeric($id)) {
        throw new InvalidArgumentException('Identifier must be a string or integer.');
    }

    $str = trim((string)$id);
    if (!preg_match('/^[1-9][0-9]{0,18}$/', $str)) {
        throw new InvalidArgumentException('Identifier must be a positive canonical decimal integer.');
    }

    if (strlen($str) < 19 || (strlen($str) === 19 && strcmp($str, (string)PHP_INT_MAX) <= 0)) {
        return (int)$str;
    }

    return $str;
}

/**
 * Require an authenticated user ID from the server-side session.
 * Never accept user_id from $_GET, $_POST, or $_REQUEST.
 * Rejects empty, 0, '0', negative, and non-canonical IDs.
 *
 * @param string $sessionKey Key in $_SESSION holding the authenticated user ID
 * @return int|string Normalized authenticated user ID
 */
function komainu_require_login(string $sessionKey = 'uid')
{
    if (session_status() === PHP_SESSION_NONE && !headers_sent()) {
        session_start();
    }
    if (!isset($_SESSION[$sessionKey])) {
        if (!headers_sent()) {
            http_response_code(401);
        }
        echo '401 Unauthorized';
        exit;
    }

    try {
        $normUid = komainu_normalize_id($_SESSION[$sessionKey]);
    } catch (Throwable $e) {
        if (!headers_sent()) {
            http_response_code(401);
        }
        echo '401 Unauthorized';
        exit;
    }

    return $normUid;
}

/**
 * Verify two-way ownership between a target resource and the authenticated session user.
 * Uses fully portable SQL without DBMS-specific LIMIT clauses.
 *
 * @param PDO $pdo Active PDO connection
 * @param string $table Target table name (must be present in $allowedTables)
 * @param string $pkColumn Primary key or resource key column (e.g., 'id', 'order_id', 'cart_id')
 * @param mixed $resourceId Request-supplied resource identifier
 * @param string $ownerColumn Owner column in the table (e.g., 'user_id', 'member_id')
 * @param mixed $sessionUserId Authenticated user ID from server-side session
 * @param array<string, array{pk: string, owner: string}> $allowedTables Map of allowed table schemas
 * @return bool True if the resource exists and belongs to $sessionUserId, false otherwise
 */
function komainu_check_ownership(
    PDO $pdo,
    string $table,
    string $pkColumn,
    $resourceId,
    string $ownerColumn,
    $sessionUserId,
    array $allowedTables
): bool {
    // Normalise and reject falsy/non-canonical IDs before database querying
    try {
        $normResourceId = komainu_normalize_id($resourceId);
        $normSessionUserId = komainu_normalize_id($sessionUserId);
    } catch (Throwable $e) {
        return false;
    }

    if (!isset($allowedTables[$table])) {
        throw new InvalidArgumentException("Table is not registered in ownership allow-list.");
    }
    $schema = $allowedTables[$table];
    if ($schema['pk'] !== $pkColumn || $schema['owner'] !== $ownerColumn) {
        throw new InvalidArgumentException("Column mismatch against registered ownership schema.");
    }

    $safeTable = komainu_validate_identifier($table, array_keys($allowedTables));
    $safePk = komainu_validate_identifier($pkColumn, [$schema['pk']]);
    $safeOwner = komainu_validate_identifier($ownerColumn, [$schema['owner']]);

    // Portable SQL: Primary key uniqueness guarantees at most one row without LIMIT
    $sql = sprintf(
        'SELECT 1 FROM %s WHERE %s = :resource_id AND %s = :owner_id',
        $safeTable,
        $safePk,
        $safeOwner
    );

    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        ':resource_id' => $normResourceId,
        ':owner_id' => $normSessionUserId,
    ]);

    return $stmt->fetchColumn() !== false;
}

/**
 * Enforce ownership or immediately terminate with HTTP 404 Not Found.
 * Returning 404 instead of 403 prevents resource ID enumeration (ADR-0004).
 * Catches missing identifier exceptions and emits 404 instead of 500.
 *
 * @return int|string Normalized resource ID for caller to safely use
 */
function komainu_enforce_ownership(
    PDO $pdo,
    string $table,
    string $pkColumn,
    $resourceId,
    string $ownerColumn,
    $sessionUserId,
    array $allowedTables
) {
    $isOwner = false;
    $normResourceId = null;
    try {
        $normResourceId = komainu_normalize_id($resourceId);
        $isOwner = komainu_check_ownership(
            $pdo,
            $table,
            $pkColumn,
            $normResourceId,
            $ownerColumn,
            $sessionUserId,
            $allowedTables
        );
    } catch (Throwable $e) {
        // Missing table/column identifiers, schema mismatch, or invalid IDs produce 404
        $isOwner = false;
    }

    if (!$isOwner || $normResourceId === null) {
        if (!headers_sent()) {
            http_response_code(404);
        }
        echo '404 Not Found';
        exit;
    }

    return $normResourceId;
}

/**
 * Sanitize dynamic ORDER BY column and direction using an exact-match allow-list.
 *
 * @param string|null $inputColumn User-supplied sort column from $_GET['sort']
 * @param array<int, string> $allowedColumns Explicitly allowed column names
 * @param string $defaultColumn Fallback column name if input is null or invalid
 * @param string|null $inputDir User-supplied sort direction ('ASC' or 'DESC')
 * @return string Safe "column ASC|DESC" fragment ready for SQL interpolation
 */
function komainu_safe_order_by(
    ?string $inputColumn,
    array $allowedColumns,
    string $defaultColumn,
    ?string $inputDir = 'ASC'
): string {
    $safeDefault = komainu_validate_identifier($defaultColumn, $allowedColumns);
    $col = ($inputColumn !== null && in_array($inputColumn, $allowedColumns, true))
        ? komainu_validate_identifier($inputColumn, $allowedColumns)
        : $safeDefault;

    $dir = (strtoupper((string)$inputDir) === 'DESC') ? 'DESC' : 'ASC';
    return $col . ' ' . $dir;
}
