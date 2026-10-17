namespace Komainu.Security.Query.Analyzers;

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

/// <summary>
/// Roslyn diagnostic analyzer detecting unsafe SQL queries constructed via string concatenation or interpolation.
/// Enforces Layer 5 parameterized query requirements of the Komainu modernization architecture.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class SqlInjectionDiagnosticAnalyzer : DiagnosticAnalyzer
{
    private static readonly LocalizableString Title = "Potential SQL Injection from string-built query";
    private static readonly LocalizableString MessageFormat = "Method '{0}' receives a SQL query constructed via string concatenation or interpolation. Use parameterized queries or safe query helpers instead.";
    private static readonly LocalizableString Description = "SQL queries constructed from string concatenation or interpolation are vulnerable to SQL Injection (CWE-89). All queries must be 100% parameterized.";
    private const string Category = "Security";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticIds.SqlInjectionDiagnosticId,
        Title,
        MessageFormat,
        Category,
        DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: Description);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    private static readonly ImmutableHashSet<string> TargetSqlMethodNames = ImmutableHashSet.Create(
        "FromSqlRaw",
        "ExecuteSqlRaw",
        "ExecuteSqlRawAsync",
        "SqlQueryRaw",
        "Query",
        "QueryAsync",
        "Execute",
        "ExecuteAsync"
    );

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterSyntaxNodeAction(AnalyzeInvocationExpression, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocationExpression(SyntaxNodeAnalysisContext context)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;

        string? methodName = null;
        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            methodName = memberAccess.Name.Identifier.Text;
        }
        else if (invocation.Expression is IdentifierNameSyntax identifier)
        {
            methodName = identifier.Identifier.Text;
        }

        if (string.IsNullOrEmpty(methodName) || methodName is null || !TargetSqlMethodNames.Contains(methodName))
        {
            return;
        }

        var arguments = invocation.ArgumentList.Arguments;
        if (arguments.Count == 0)
        {
            return;
        }

        var sqlArgument = arguments[0].Expression;

        if (IsUnsafeStringExpression(sqlArgument, context.SemanticModel))
        {
            var diagnostic = Diagnostic.Create(Rule, sqlArgument.GetLocation(), methodName);
            context.ReportDiagnostic(diagnostic);
        }
    }

    private static bool IsUnsafeStringExpression(ExpressionSyntax expression, SemanticModel semanticModel)
    {
        // 1. String interpolation: $"SELECT * FROM users WHERE id = {userId}"
        if (expression is InterpolatedStringExpressionSyntax)
        {
            return true;
        }

        // 2. Binary string concatenation: "SELECT * FROM users WHERE id = " + userId
        if (expression is BinaryExpressionSyntax binary && binary.IsKind(SyntaxKind.AddExpression))
        {
            // Verify if one of the operands is not a compile-time constant string
            var constant = semanticModel.GetConstantValue(expression);
            if (!constant.HasValue)
            {
                return true;
            }
        }

        // 3. Invocation of string.Format(...) or string.Concat(...)
        if (expression is InvocationExpressionSyntax invocation)
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var invokedName = memberAccess.Name.Identifier.Text;
                if (invokedName == "Format" || invokedName == "Concat")
                {
                    return true;
                }
            }
        }

        // 4. Identifier reference to a non-constant string variable
        if (expression is IdentifierNameSyntax identifier)
        {
            var constant = semanticModel.GetConstantValue(identifier);
            if (!constant.HasValue)
            {
                var symbol = semanticModel.GetSymbolInfo(identifier).Symbol;
                if (symbol is ILocalSymbol || symbol is IParameterSymbol)
                {
                    return true;
                }
                if (symbol is IFieldSymbol field && !field.IsConst)
                {
                    return true;
                }
            }
        }

        return false;
    }
}
