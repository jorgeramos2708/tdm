using TDM.Models;

namespace TDM.Collectors.TSplus;

public sealed record TsplusLogSource(
    string Componente,
    string Ruta,
    bool EsDirectorio,
    bool Existe,
    DateTimeOffset? UltimaModificacion,
    long? TamanoBytes,
    DiagnosticLayer Capa = DiagnosticLayer.Tsplus,
    TsplusProduct Producto = TsplusProduct.RemoteAccess,
    bool FuenteOpcional = true);
