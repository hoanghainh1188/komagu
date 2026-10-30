namespace Komagu.Security.Query;

using System.Linq.Expressions;
using System.Reflection;

/// <summary>
/// Type-safe, expression-tree-based dynamic query helpers eliminating dynamic SQL string concatenation.
/// </summary>
public static class SafeQueryHelper
{
    /// <summary>
    /// Applies dynamic sorting to an IQueryable safely using expression trees without building dynamic SQL strings.
    /// </summary>
    public static IQueryable<T> ApplySafeOrderBy<T>(
        this IQueryable<T> query,
        SafeSortAllowList allowList,
        string columnName,
        SortDirection direction = SortDirection.Ascending)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(allowList);

        var validColumn = allowList.ValidateColumnName(columnName);

        var entityType = typeof(T);
        var property = entityType.GetProperty(validColumn, BindingFlags.IgnoreCase | BindingFlags.Public | BindingFlags.Instance)
            ?? throw new ArgumentException($"Property '{validColumn}' does not exist on entity '{entityType.Name}'");

        var parameter = Expression.Parameter(entityType, "e");
        var propertyAccess = Expression.MakeMemberAccess(parameter, property);
        var orderByExpression = Expression.Lambda(propertyAccess, parameter);

        var methodName = direction == SortDirection.Descending ? "OrderByDescending" : "OrderBy";
        var resultExpression = Expression.Call(
            typeof(Queryable),
            methodName,
            new Type[] { entityType, property.PropertyType },
            query.Expression,
            Expression.Quote(orderByExpression));

        return query.Provider.CreateQuery<T>(resultExpression);
    }
}
