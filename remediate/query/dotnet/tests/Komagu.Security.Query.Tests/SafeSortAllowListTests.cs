namespace Komagu.Security.Query.Tests;

using System.Security;
using Komagu.Security.Query;
using Xunit;

public class SafeSortAllowListTests
{
    private readonly SafeSortAllowList _allowList;

    public SafeSortAllowListTests()
    {
        _allowList = new SafeSortAllowList(new[] { "id", "created_at", "total_amount", "status" });
    }

    [Theory]
    [InlineData("created_at", "created_at")]
    [InlineData("total_amount", "total_amount")]
    [InlineData("ID", "id")]
    [InlineData("status", "status")]
    public void ValidateColumnName_WhenColumnInAllowList_ReturnsColumnName(string input, string expected)
    {
        var result = _allowList.ValidateColumnName(input);
        Assert.Equal(expected, result, ignoreCase: true);
    }

    [Theory]
    [InlineData("credit_card_number")]
    [InlineData("password_hash")]
    [InlineData("internal_notes")]
    public void ValidateColumnName_WhenColumnNotInAllowList_ThrowsSecurityException(string unauthorizedColumn)
    {
        var ex = Assert.Throws<SecurityException>(() => _allowList.ValidateColumnName(unauthorizedColumn));
        Assert.Contains("Unauthorized column name", ex.Message);
    }

    [Theory]
    [InlineData("id; DROP TABLE orders;--")]
    [InlineData("created_at' OR '1'='1")]
    [InlineData("total_amount UNION SELECT * FROM users")]
    [InlineData("status/**/")]
    [InlineData("id, status")]
    [InlineData("../etc/passwd")]
    public void ValidateColumnName_WhenInjectionPayloadSupplied_ThrowsSecurityException(string attackPayload)
    {
        var ex = Assert.Throws<SecurityException>(() => _allowList.ValidateColumnName(attackPayload));
        Assert.Contains("SQL injection", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildSortClause_ConstructsSafeSqlClause_Correctly()
    {
        Assert.Equal("created_at ASC", _allowList.BuildSortClause("created_at", SortDirection.Ascending));
        Assert.Equal("total_amount DESC", _allowList.BuildSortClause("total_amount", SortDirection.Descending));
    }
}
