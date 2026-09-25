using Avalonia.Media.Fonts;

namespace TDM.Gui.Avalonia;

/// <summary>
/// Fuente monoespaciada integrada para que el cronómetro conserve exactamente
/// la misma apariencia en cualquier equipo, sin depender de fuentes de Windows.
/// </summary>
public sealed class TdmFontCollection : EmbeddedFontCollection
{
    public TdmFontCollection()
        : base(
            new Uri("fonts:Tdm", UriKind.Absolute),
            new Uri($"avares://{typeof(TdmFontCollection).Assembly.GetName().Name}/Assets/Fonts", UriKind.Absolute))
    {
    }
}
