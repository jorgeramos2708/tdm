using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using TDM.Models;

namespace TDM.Core;

/// <summary>
/// Registro versionado de parsers con schema registry integrado.
/// Permite registro dinámico, versionado semántico, y validación de schemas.
/// </summary>
public sealed class ParserRegistry : IDisposable
{
    private readonly ConcurrentDictionary<string, ParserRegistration> _parsers = new();
    private readonly ConcurrentDictionary<string, SchemaDefinition> _schemas = new();
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly string _registryPath;
    private readonly FileSystemWatcher? _watcher;
    private bool _disposed;

    public ParserRegistry(string? registryPath = null)
    {
        _registryPath = registryPath ?? Path.Combine(AppContext.BaseDirectory, "parsers");
        Directory.CreateDirectory(_registryPath);

        // Registrar parsers built-in
        RegisterBuiltInParsers();

        // Cargar parsers externos si existen
        LoadExternalParsers();

        // Watcher para hot-reload
        _watcher = new FileSystemWatcher(_registryPath, "*.json")
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime,
            EnableRaisingEvents = true
        };
        _watcher.Changed += OnSchemaChanged;
        _watcher.Created += OnSchemaCreated;
        _watcher.Deleted += OnSchemaDeleted;
    }

    /// <summary>
    /// Registra un parser con su schema versionado.
    /// </summary>
    public ParserRegistration Register(string parserId, ParserDefinition definition, SchemaDefinition schema)
    {
        if (string.IsNullOrWhiteSpace(parserId))
            throw new ArgumentException("Parser ID requerido", nameof(parserId));
        if (definition == null) throw new ArgumentNullException(nameof(definition));
        if (schema == null) throw new ArgumentNullException(nameof(schema));

        // Validar schema
        var validation = ValidateSchema(schema);
        if (!validation.IsValid)
            throw new ArgumentException($"Schema inválido: {string.Join(", ", validation.Errors)}");

        var registration = new ParserRegistration(
            ParserId: parserId,
            Definition: definition,
            Schema: schema,
            RegisteredAt: DateTimeOffset.UtcNow,
            AssemblyVersion: Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown"
        );

        _lock.EnterWriteLock();
        try
        {
            _parsers[parserId] = registration;
            _schemas[schema.SchemaId] = schema;
        }
        finally
        {
            _lock.ExitWriteLock();
        }

        // Persistir
        PersistParser(registration);
        PersistSchema(schema);

        return registration;
    }

    /// <summary>
    /// Obtiene un parser por ID.
    /// </summary>
    public ParserRegistration? GetParser(string parserId)
    {
        _lock.EnterReadLock();
        try
        {
            return _parsers.TryGetValue(parserId, out var reg) ? reg : null;
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    /// Obtiene todos los parsers registrados.
    /// </summary>
    public IReadOnlyList<ParserRegistration> GetAllParsers()
    {
        _lock.EnterReadLock();
        try
        {
            return _parsers.Values.ToImmutableList();
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    /// Obtiene un schema por ID.
    /// </summary>
    public SchemaDefinition? GetSchema(string schemaId)
    {
        _lock.EnterReadLock();
        try
        {
            return _schemas.TryGetValue(schemaId, out var schema) ? schema : null;
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    /// Valida un payload contra un schema.
    /// </summary>
    public ValidationResult Validate(string schemaId, string jsonPayload)
    {
        var schema = GetSchema(schemaId);
        if (schema == null)
            return ValidationResult.Fail($"Schema no encontrado: {schemaId}");

        try
        {
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            JsonSerializer.Deserialize(jsonPayload, schema.ClrType, options);
            return ValidationResult.Ok();
        }
        catch (JsonException ex)
        {
            return ValidationResult.Fail(ex.Message);
        }
    }

    /// <summary>
    /// Obtiene todas las versiones de un schema.
    /// </summary>
    public IReadOnlyList<SchemaDefinition> GetSchemaVersions(string schemaName)
    {
        _lock.EnterReadLock();
        try
        {
            return _schemas.Values
                .Where(s => s.SchemaName.Equals(schemaName, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(s => s.Version, new VersionComparer())
                .ToImmutableList();
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    /// <summary>
    /// Obtiene la versión más reciente de un schema.
    /// </summary>
    public SchemaDefinition? GetLatestSchema(string schemaName)
    {
        return GetSchemaVersions(schemaName).FirstOrDefault();
    }

    private void RegisterBuiltInParsers()
    {
        // Built-in parsers are registered by higher-level projects via Register()
        // This method is kept for extensibility
    }

    private void LoadExternalParsers()
    {
        try
        {
            var files = Directory.GetFiles(_registryPath, "*.parser.json");
            foreach (var file in files)
            {
                try
                {
                    var json = File.ReadAllText(file);
                    var registration = JsonSerializer.Deserialize<ParserRegistration>(json, ParserRegistryJsonContext.Default.ParserRegistration);
                    if (registration != null)
                    {
                        _parsers[registration.ParserId] = registration;
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error cargando parser {file}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error cargando parsers externos: {ex.Message}");
        }
    }

    private void PersistParser(ParserRegistration registration)
    {
        try
        {
            var file = Path.Combine(_registryPath, $"{registration.ParserId}.parser.json");
            var json = JsonSerializer.Serialize(registration, ParserRegistryJsonContext.Default.ParserRegistration);
            File.WriteAllText(file, json);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error persistiendo parser: {ex.Message}");
        }
    }

    private void PersistSchema(SchemaDefinition schema)
    {
        try
        {
            var file = Path.Combine(_registryPath, $"{schema.SchemaId}.schema.json");
            var json = JsonSerializer.Serialize(schema, ParserRegistryJsonContext.Default.SchemaDefinition);
            File.WriteAllText(file, json);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error persistiendo schema: {ex.Message}");
        }
    }

    private void OnSchemaChanged(object sender, FileSystemEventArgs e)
    {
        try
        {
            if (e.Name?.EndsWith(".schema.json") == true)
            {
                var json = File.ReadAllText(e.FullPath);
                var schema = JsonSerializer.Deserialize<SchemaDefinition>(json, ParserRegistryJsonContext.Default.SchemaDefinition);
                if (schema != null)
                {
                    _schemas[schema.SchemaId] = schema;
                }
            }
            else if (e.Name?.EndsWith(".parser.json") == true)
            {
                var json = File.ReadAllText(e.FullPath);
                var registration = JsonSerializer.Deserialize<ParserRegistration>(json, ParserRegistryJsonContext.Default.ParserRegistration);
                if (registration != null)
                {
                    _parsers[registration.ParserId] = registration;
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error recargando schema/parser: {ex.Message}");
        }
    }

    private void OnSchemaCreated(object sender, FileSystemEventArgs e)
    {
        OnSchemaChanged(sender, e);
    }

    private void OnSchemaDeleted(object sender, FileSystemEventArgs e)
    {
        try
        {
            var fileName = Path.GetFileNameWithoutExtension(e.Name);
            if (string.IsNullOrEmpty(fileName)) return;

            var id = fileName;
            if (e.Name?.EndsWith(".schema.json") == true)
            {
                id = id.Replace(".schema", "");
                _schemas.TryRemove(id, out _);
            }
            else if (e.Name?.EndsWith(".parser.json") == true)
            {
                id = id.Replace(".parser", "");
                _parsers.TryRemove(id, out _);
            }
        }
        catch { }
    }

    private static ValidationResult ValidateSchema(SchemaDefinition schema)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(schema.SchemaId))
            errors.Add("SchemaId requerido");
        if (string.IsNullOrWhiteSpace(schema.SchemaName))
            errors.Add("SchemaName requerido");
        if (string.IsNullOrWhiteSpace(schema.Version))
            errors.Add("Version requerida");
        if (schema.ClrType == null)
            errors.Add("ClrType requerido");
        if (string.IsNullOrWhiteSpace(schema.JsonSchema))
            errors.Add("JsonSchema requerido");

        // Validar que el JSON schema es válido
        try
        {
            JsonSerializer.Deserialize<object>(schema.JsonSchema);
        }
        catch (Exception ex)
        {
            errors.Add($"JsonSchema inválido: {ex.Message}");
        }

        return errors.Count == 0
            ? ValidationResult.Ok()
            : ValidationResult.Fail(string.Join("; ", errors));
    }

    

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _watcher?.Dispose();
        _lock.Dispose();
    }
}

/// <summary>
/// Definición de un parser.
/// </summary>
public sealed record ParserDefinition(
    string ParserId,
    string DisplayName,
    string Description,
    IReadOnlyList<string> SupportedFormats,
    string FactoryType,
    IReadOnlyList<string> SupportedExtensions,
    int Priority
);

/// <summary>
/// Definición de schema versionado.
/// </summary>
public sealed record SchemaDefinition(
    string SchemaId,
    string SchemaName,
    string Version,
    string SchemaVersion,
    string JsonSchema,
    Type ClrType,
    string Description,
    DateTimeOffset CreatedAt
);

/// <summary>
/// Registro completo de un parser con su schema.
/// </summary>
public sealed record ParserRegistration(
    string ParserId,
    ParserDefinition Definition,
    SchemaDefinition Schema,
    DateTimeOffset RegisteredAt,
    string AssemblyVersion
);

/// <summary>
/// Resultado de validación.
/// </summary>
public sealed record ValidationResult(
    bool IsValid,
    IReadOnlyList<string> Errors)
{
    public static ValidationResult Ok() => new(true, ImmutableList<string>.Empty);
    public static ValidationResult Fail(string error) => new(false, ImmutableList.Create(error));
    public static ValidationResult Fail(IEnumerable<string> errors) => new(false, errors.ToImmutableList());
}

/// <summary>
    /// Comparador de versiones semánticas.
    /// </summary>
    sealed class VersionComparer : IComparer<string>
    {
        public int Compare(string? x, string? y)
        {
            if (x == null && y == null) return 0;
            if (x == null) return -1;
            if (y == null) return 1;

            var vx = Version.TryParse(x, out var vxParsed) ? vxParsed : new Version(0, 0);
            var vy = Version.TryParse(y, out var vyParsed) ? vyParsed : new Version(0, 0);
            return vy.CompareTo(vx); // Descending
        }
    }

/// <summary>
/// Source generation para JSON serialization.
/// </summary>
[JsonSerializable(typeof(ParserRegistration))]
[JsonSerializable(typeof(SchemaDefinition))]
[JsonSerializable(typeof(ParserDefinition))]
[JsonSerializable(typeof(SchemaDefinition))]
[JsonSerializable(typeof(ParserRegistration))]
internal partial class ParserRegistryJsonContext : JsonSerializerContext
{
}