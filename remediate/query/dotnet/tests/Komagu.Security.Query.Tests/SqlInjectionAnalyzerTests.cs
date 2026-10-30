namespace Komagu.Security.Query.Tests;

using System.Collections.Immutable;
using Komagu.Security.Query.Analyzers;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Xunit;

public class SqlInjectionAnalyzerTests
{
    private static async Task<ImmutableArray<Diagnostic>> RunAnalyzerAsync(string source)
    {
        var syntaxTree = CSharpSyntaxTree.ParseText(source);

        var references = new MetadataReference[]
        {
            MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Enumerable).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Runtime.AssemblyTargetedPatchBandAttribute).Assembly.Location)
        };

        var compilation = CSharpCompilation.Create(
            "TestCompilation",
            new[] { syntaxTree },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var analyzer = new SqlInjectionDiagnosticAnalyzer();
        var compilationWithAnalyzers = compilation.WithAnalyzers(ImmutableArray.Create<DiagnosticAnalyzer>(analyzer));
        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
    }

    [Fact]
    public async Task Analyzer_FlagsBinaryConcatenationInFromSqlRaw()
    {
        var testCode = @"
namespace TestApp;

public class SampleService
{
    public void RunQuery(string orderId)
    {
        FakeDb.FromSqlRaw(""SELECT * FROM orders WHERE id = "" + orderId);
    }
}

public static class FakeDb
{
    public static void FromSqlRaw(string sql) { }
}
";
        var diagnostics = await RunAnalyzerAsync(testCode);

        Assert.Single(diagnostics);
        Assert.Equal(DiagnosticIds.SqlInjectionDiagnosticId, diagnostics[0].Id);
        Assert.Contains("FromSqlRaw", diagnostics[0].GetMessage());
    }

    [Fact]
    public async Task Analyzer_FlagsStringInterpolationInFromSqlRaw()
    {
        var testCode = @"
namespace TestApp;

public class SampleService
{
    public void RunQuery(string orderId)
    {
        FakeDb.FromSqlRaw($""SELECT * FROM orders WHERE id = {orderId}"");
    }
}

public static class FakeDb
{
    public static void FromSqlRaw(string sql) { }
}
";
        var diagnostics = await RunAnalyzerAsync(testCode);

        Assert.Single(diagnostics);
        Assert.Equal(DiagnosticIds.SqlInjectionDiagnosticId, diagnostics[0].Id);
    }

    [Fact]
    public async Task Analyzer_DoesNotFlagConstantStringLiteral()
    {
        var testCode = @"
namespace TestApp;

public class SampleService
{
    public void RunQuery()
    {
        FakeDb.FromSqlRaw(""SELECT * FROM orders WHERE status = 'ACTIVE'"");
    }
}

public static class FakeDb
{
    public static void FromSqlRaw(string sql) { }
}
";
        var diagnostics = await RunAnalyzerAsync(testCode);
        Assert.Empty(diagnostics);
    }

    [Fact]
    public async Task Analyzer_DoesNotFlagUnrelatedMethodConcatenation()
    {
        var testCode = @"
namespace TestApp;

public class SampleService
{
    public void LogInfo(string username)
    {
        Logger.Log(""User logged in: "" + username);
    }
}

public static class Logger
{
    public static void Log(string msg) { }
}
";
        var diagnostics = await RunAnalyzerAsync(testCode);
        Assert.Empty(diagnostics);
    }
}
