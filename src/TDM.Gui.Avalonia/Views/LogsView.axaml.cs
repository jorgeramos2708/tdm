using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using TDM.Gui.Avalonia.ViewModels;

namespace TDM.Gui.Avalonia.Views;

public partial class LogsView : UserControl
{
    public LogsView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}