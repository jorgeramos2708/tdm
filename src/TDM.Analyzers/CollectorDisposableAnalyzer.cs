using System;
using System.Collections.Immutable;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace TDM.Analyzers;

/// <summary>
/// Analyzer que fuerza que todos los collectors implementen IDisposable correctamente.
/// TDM.Core.IReadOnlyCollector no hereda IDisposable, pero los collectors que usan recursos
/// no administrados (EventLog, FileSystemWatcher, etc.) deben implementar IDisposable
/// y ser registrados en el contenedor de dependencias para disposal ordenado.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class CollectorDisposableAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "TDM001";
    private const string Category = "TDM.Correctness";

    private static readonly LocalizableString Title = "Collector debe implementar IDisposable si usa recursos no administrados";
    private static readonly LocalizableString MessageFormat = "El tipo '{0}' implementa IReadOnlyCollector y usa recursos no administrados; debe implementar IDisposable";
    private static readonly LocalizableString Description = "Collectors que usan EventLog, FileSystemWatcher, ManagementObjectSearcher, etc. deben implementar IDisposable para liberación determinista.";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId, Title, MessageFormat, Category,
        DiagnosticSeverity.Warning, isEnabledByDefault: true,
        description: Description);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSymbolAction(AnalyzeNamedType, SymbolKind.NamedType);
    }

    private void AnalyzeNamedType(SymbolAnalysisContext context)
    {
        var namedType = (INamedTypeSymbol)context.Symbol;

        // Solo clases que implementan IReadOnlyCollector
        var collectorInterface = context.Compilation.GetTypeByMetadataName("TDM.Core.IReadOnlyCollector");
        if (collectorInterface is null || !namedType.AllInterfaces.Contains(collectorInterface))
            return;

        // Si ya implementa IDisposable, OK
        var disposableInterface = context.Compilation.GetSpecialType(SpecialType.System_IDisposable);
        if (namedType.AllInterfaces.Contains(disposableInterface))
            return;

        // Verificar si usa recursos no administrados conocidos
        if (UsesUnmanagedResources(namedType, context.Compilation))
        {
            var diagnostic = Diagnostic.Create(Rule, namedType.Locations[0], namedType.Name);
            context.ReportDiagnostic(diagnostic);
        }
    }

    private static bool UsesUnmanagedResources(INamedTypeSymbol type, Compilation compilation)
    {
        // Verificar miembros del tipo (campos, propiedades, métodos) por tipos conocidos
        var unmanagedTypes = new[]
        {
            "System.Diagnostics.Eventing.Reader.EventLogWatcher",
            "System.Diagnostics.EventLog",
            "System.IO.FileSystemWatcher",
            "System.Management.ManagementObjectSearcher",
            "System.Management.ManagementEventWatcher",
            "System.Net.Sockets.TcpListener",
            "System.Net.Http.HttpClient",
            "System.Timers.Timer",
            "System.Threading.Timer",
            "System.IO.Stream",
            "System.Net.WebSockets.ClientWebSocket",
            "Microsoft.Win32.RegistryKey"
        };

        foreach (var member in type.GetMembers())
        {
            if (member is IFieldSymbol field)
            {
                var typeName = field.Type.ToDisplayString();
                if (IsUnmanagedType(typeName, unmanagedTypes)) return true;
            }
            else if (member is IPropertySymbol prop)
            {
                var typeName = prop.Type.ToDisplayString();
                if (IsUnmanagedType(typeName, unmanagedTypes)) return true;
            }
            else if (member is IMethodSymbol method && method.MethodKind == MethodKind.Constructor)
            {
                // Verificar si el constructor crea instancias de tipos no administrados
                var syntaxRef = member.DeclaringSyntaxReferences.FirstOrDefault();
                if (syntaxRef is not null)
                {
                    var syntax = syntaxRef.GetSyntax();
                    var walker = new ObjectCreationWalker(unmanagedTypes);
                    walker.Visit(syntax);
                    if (walker.Found) return true;
                }
            }
        }

        return false;
    }

    private static bool IsUnmanagedType(string typeName, string[] unmanagedTypes)
    {
        foreach (var u in unmanagedTypes)
        {
            if (typeName.StartsWith(u, StringComparison.Ordinal))
                return true;
            
            var parts = u.Split('.');
            var shortName = parts[parts.Length - 1];
            if (typeName.Contains($".{shortName}", StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private sealed class ObjectCreationWalker : CSharpSyntaxWalker
    {
        private readonly string[] _unmanagedTypes;
        public bool Found { get; private set; }

        public ObjectCreationWalker(string[] unmanagedTypes)
        {
            _unmanagedTypes = unmanagedTypes;
        }

        public override void VisitObjectCreationExpression(ObjectCreationExpressionSyntax node)
        {
            var typeName = node.Type?.ToString() ?? "";
            foreach (var u in _unmanagedTypes)
            {
                var parts = u.Split('.');
                var shortName = parts[parts.Length - 1];
                if (typeName.Contains(shortName, StringComparison.OrdinalIgnoreCase))
                {
                    Found = true;
                    return;
                }
            }
            base.VisitObjectCreationExpression(node);
        }
    }
}