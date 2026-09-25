using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using TDM.Notifications;

namespace TDM.Gui.Avalonia.Views;

internal sealed class PortableNotificationCoordinator : IDisposable
{
    private const int MaxVisible = 4;
    private const int Gap = 10;
    private readonly Window _mainWindow;
    private readonly List<PortableNotificationWindow> _visible = [];

    public PortableNotificationCoordinator(Window mainWindow)
    {
        _mainWindow = mainWindow;
    }

    public void Show(IReadOnlyList<IncidentNotification> notifications)
    {
        var visible = notifications.Where(x => x.Transition != NotificationTransition.Recovered).ToList();
        if (visible.Count == 0) return;
        Dispatcher.UIThread.Post(() =>
        {
            foreach (var notification in visible)
                ShowOne(notification);
        });
    }

    private void ShowOne(IncidentNotification notification)
    {
        while (_visible.Count >= MaxVisible)
            _visible[0].Close();

        var window = new PortableNotificationWindow(notification, ActivateMainWindow);
        window.Opened += (_, _) => Reposition();
        window.Closed += (_, _) =>
        {
            _visible.Remove(window);
            Reposition();
        };
        _visible.Add(window);
        window.Show();
    }

    private void ActivateMainWindow()
    {
        if (!_mainWindow.IsVisible) _mainWindow.Show();
        _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
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

    public void Dispose()
    {
        foreach (var window in _visible.ToArray()) window.Close();
        _visible.Clear();
    }
}
