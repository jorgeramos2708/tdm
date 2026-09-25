namespace TDM.Application;

/// <summary>
/// Parser puro de la mini-CLI de feedback (TDM --feedback-confirm|--feedback-discard ...).
/// Es la vía sin-GUI para alimentar el historial verificado que pondera el ranking.
/// Pineado por tests; Program.cs solo lo ejecuta. No toca disco.
/// </summary>
public static class FeedbackCommandParser
{
    public const string ConfirmFlag = "--feedback-confirm";
    public const string DiscardFlag = "--feedback-discard";
    public const string HelpFlag = "--feedback-help";

    public const string Usage = "Uso: TDM --feedback-confirm|--feedback-discard --id <candidato> [--component <texto>] [--score <0-100>] [--confidence <texto>] [--note <texto>] [--technician <nombre>] [--root <ruta>] | TDM --feedback-help";

    public sealed record FeedbackCommand(
        bool Help,
        bool Confirm,
        string CandidateId,
        string Componente,
        int Puntaje,
        string Confianza,
        string? Nota,
        string? Tecnico,
        string? Root);

    public static bool IsFeedbackInvocation(string[] args)
        => args.Length > 0 && (args[0] == ConfirmFlag || args[0] == DiscardFlag || args[0] == HelpFlag);

    public static bool TryParse(string[] args, out FeedbackCommand? command, out string error)
    {
        command = null;
        error = "";
        if (!IsFeedbackInvocation(args)) { error = "No es una invocación de feedback."; return false; }
        if (args[0] == HelpFlag)
        {
            command = new FeedbackCommand(true, true, "", "N/D", 0, "N/D", null, null, null);
            return true;
        }
        var confirm = args[0] == ConfirmFlag;
        string? id = null;
        var component = "N/D";
        var confidence = "N/D";
        string? note = null;
        string? tech = null;
        string? root = null;
        var score = 0;
        for (var i = 1; i < args.Length; i++)
        {
            string? value = i + 1 < args.Length ? args[i + 1] : null;
            switch (args[i])
            {
                case "--id": id = value; i++; break;
                case "--component": component = value ?? "N/D"; i++; break;
                case "--score":
                    if (!int.TryParse(value, out score) || score < 0 || score > 100) { error = "--score debe ser entero 0..100."; return false; }
                    i++;
                    break;
                case "--confidence": confidence = value ?? "N/D"; i++; break;
                case "--note": note = value; i++; break;
                case "--technician": tech = value; i++; break;
                case "--root": root = value; i++; break;
                default: error = "Parámetro desconocido: " + args[i] + "."; return false;
            }
        }
        if (string.IsNullOrWhiteSpace(id)) { error = "Falta --id <candidato>."; return false; }
        command = new FeedbackCommand(false, confirm, id.Trim(),
            string.IsNullOrWhiteSpace(component) ? "N/D" : component.Trim(), score,
            string.IsNullOrWhiteSpace(confidence) ? "N/D" : confidence.Trim(),
            string.IsNullOrWhiteSpace(note) ? null : note,
            string.IsNullOrWhiteSpace(tech) ? null : tech,
            string.IsNullOrWhiteSpace(root) ? null : root);
        return true;
    }
}
