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
 * 3. Resource IDs and owner IDs are bound using PDO prepared statements.
 * 4. Mismatches emit HTTP 404 Not Found and immediately call exit() (prevents P4 check-without-stop).
 */

declare(strict_types=1);

/**
 * Validate that an identifier (table or column name) is strictly in the allow-list
 * and matches safe alphanumeric/underscore syntax.
 *
 * @param string $identifier Candidate table or column name
 * @param array<int, string> $allowList Allowed identifier literals
 * @return string Validated identifier
 * @throws InvalidArgumentException If identifier is not in the allow-list
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
 * Require an authenticated user ID from the server-side session.
 * Never accept user_id from $_GET, $_POST, or $_REQUEST.
 *
 * @param string $sessionKey Key in $_SESSION holding the authenticated user ID
 * @return int|string Authenticated user ID
 */
function komainu_require_login(string $sessionKey = 'uid')
{
    if (session_status() === PHP_SESSION_NONE && !headers_sent()) {
        session_start();
    }
    if (!isset($_SESSION[$sessionKey]) || $_SESSION[$sessionKey] === '') {
        if (!headers_sent()) {
            http_response_code(401);
        }
        echo '401 Unauthorized';
        exit;
    }
    return $_SESSION[$sessionKey];
}

/**
 * Verify two-way ownership between a target resource and the authenticated session user.
 *
 * @param PDO $pdo Active PDO connection
 * @param string $table Target table name (must be present in $allowedTables)
 * @param string $pkColumn Primary key or resource key column (e.g., 'id', 'order_id', 'cart_id')
 * @param int|string $resourceId Request-supplied resource identifier
 * @param string $ownerColumn Owner column in the table (e.g., 'user_id', 'member_id')
 * @param int|string $sessionUserId Authenticated user ID from server-side session
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

    $sql = sprintf(
        'SELECT 1 FROM %s WHERE %s = :resource_id AND %s = :owner_id LIMIT 1',
        $safeTable,
        $safePk,
        $safeOwner
    );

    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        ':resource_id' => $resourceId,
        ':owner_id' => $sessionUserId,
    ]);

    return $stmt->fetchColumn() !== false;
}

/**
 * Enforce ownership or immediately terminate with HTTP 404 Not Found.
 * Returning 404 instead of 403 prevents resource ID enumeration (ADR-0004).
 */
function komainu_enforce_ownership(
    PDO $pdo,
    string $table,
    string $pkColumn,
    $resourceId,
    string $ownerColumn,
    $sessionUserId,
    array $allowedTables
): void {
    $isOwner = komainu_check_ownership(
        $pdo,
        $table,
        $pkColumn,
        $resourceId,
        $ownerColumn,
        $sessionUserId,
        $allowedTables
    );

    if (!$isOwner) {
        if (!headers_sent()) {
            http_response_code(404);
        }
        echo '404 Not Found';
        exit;
    }
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
