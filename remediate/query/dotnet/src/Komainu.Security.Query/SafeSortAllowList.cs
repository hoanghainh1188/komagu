namespace Komainu.Security.Query;

using System.Security;
using System.Text.RegularExpressions;

/// <summary>
/// Direction for dynamic query sorting.
/// </summary>
public enum SortDirection
{
    Ascending,
    Descending
}

/// <summary>
/// Strict allow-list validator for dynamic column names and sort clauses.
/// Prevents SQL injection via dynamic ORDER BY clauses.
/// </summary>
public sealed class SafeSortAllowList
{
    private static readonly Regex SafeIdentifierRegex = new("^[a-zA-Z_][a-zA-Z0-9_]*$", RegexOptions.Compiled);
    private readonly HashSet<string> _allowedColumns;

    public SafeSortAllowList(IEnumerable<string> allowedColumns)
    {
        ArgumentNullException.ThrowIfNull(allowedColumns);

        _allowedColumns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var col in allowedColumns)
        {
            if (string.IsNullOrWhiteSpace(col) || !SafeIdentifierRegex.IsMatch(col))
            {
                throw new ArgumentException($"Invalid column identifier in allow-list: '{col}'. Must match ^[a-zA-Z_][a-zA-Z0-9_]*$", nameof(allowedColumns));
            }
            _allowedColumns.Add(col);
        }
    }

    /// <summary>
    /// Validates that the requested column name is strictly within the allow-list and contains no illegal characters.
    /// Throws SecurityException on validation failure.
    /// </summary>
    public string ValidateColumnName(string columnName)
    {
        if (string.IsNullOrWhiteSpace(columnName))
        {
            throw new SecurityException("Column name cannot be null or empty.");
        }

        var trimmed = columnName.Trim();

        // 1. Check for illegal characters or SQL injection indicators
        if (!SafeIdentifierRegex.IsMatch(trimmed))
        {
            throw new SecurityException($"Potential SQL injection detected in column name: '{columnName}'. Illegal characters detected.");
        }

        // 2. Check if explicitly in allow-list
        if (!_allowedColumns.Contains(trimmed))
        {
            throw new SecurityException($"Unauthorized column name requested: '{columnName}'. Column is not in the allowed sort list.");
        }

        return trimmed;
    }

    /// <summary>
    /// Validates and constructs a safe ORDER BY clause (e.g. "created_at ASC").
    /// </summary>
    public string BuildSortClause(string columnName, SortDirection direction = SortDirection.Ascending)
    {
        var validColumn = ValidateColumnName(columnName);
        var dirString = direction == SortDirection.Descending ? "DESC" : "ASC";
        return $"{validColumn} {dirString}";
    }
}
