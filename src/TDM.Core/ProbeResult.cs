namespace TDM.Core;

/// <summary>
/// Resultado explícito de una lectura de solo lectura. Evita que una excepción de acceso
/// se convierta accidentalmente en "sin problema observado" o "ausente".
/// </summary>
public enum ProbeState
{
    Available,
    Absent,
    Unavailable,
    AccessDenied,
    Error
}

public readonly record struct ProbeResult<T>(ProbeState State, T? Value, string? Detail = null)
{
    public bool IsAvailable => State == ProbeState.Available;
    public bool IsAbsent => State == ProbeState.Absent;
    public bool IsUnavailable => State is ProbeState.Unavailable or ProbeState.AccessDenied or ProbeState.Error;

    public static ProbeResult<T> Available(T? value) => new(ProbeState.Available, value);
    public static ProbeResult<T> Absent(string detail = "Ausencia confirmada") => new(ProbeState.Absent, default, detail);
    public static ProbeResult<T> Unavailable(string detail) => new(ProbeState.Unavailable, default, detail);
    public static ProbeResult<T> AccessDenied(string detail) => new(ProbeState.AccessDenied, default, detail);
    public static ProbeResult<T> Error(string detail) => new(ProbeState.Error, default, detail);

    public string StatusText => State switch
    {
        ProbeState.Available => "Disponible",
        ProbeState.Absent => "Ausente confirmado",
        ProbeState.AccessDenied => "Acceso denegado",
        ProbeState.Unavailable => "No disponible",
        _ => "Error de lectura"
    };
}
