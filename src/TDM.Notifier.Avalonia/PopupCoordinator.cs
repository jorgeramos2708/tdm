using Avalonia;
using TDM.Notifications;

namespace TDM.Notifier.Avalonia;

internal sealed class PopupCoordinator
{
    private const int MaxVisible = 4;
    private const int Gap = 10;
    private readonly List<PopupWindow> _visible = [];

    public void Show(IncidentNotification notification)
    {
        if (notification.Transition == NotificationTransition.Recovered) return;
        while (_visible.Count >= MaxVisible)
            _visible[0].Close();

        var window = new PopupWindow(notification);
        window.Opened += (_, _) => Reposition();
        window.Closed += (_, _) =>
        {
            _visible.Remove(window);
            Reposition();
        };
        _visible.Add(window);
        window.Show();
    }

    private void Reposition()
    {
        foreach (var group in _visible.Where(x => x.IsVisible).GroupBy(x => x.Screens.Primary))
        {
            var screen = group.Key;
            if (screen is null) continue;
            var work = screen.WorkingArea;
            var bottom = work.Bottom - Gap;
            foreach (var window in group.Reverse())
            {
                var width = Math.Max(1, (int)Math.Ceiling(window.Bounds.Width * screen.Scaling));
                var height = Math.Max(1, (int)Math.Ceiling(window.Bounds.Height * screen.Scaling));
                var x = Math.Max(work.X + Gap, work.Right - width - Gap);
                bottom -= height;
                var y = Math.Max(work.Y + Gap, bottom);
                window.Position = new PixelPoint(x, y);
                bottom -= Gap;
            }
        }
    }
}
