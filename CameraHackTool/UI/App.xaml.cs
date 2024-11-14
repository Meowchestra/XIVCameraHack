namespace CameraHackTool.UI;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App
{
    [STAThread]
    public static void Main()
    {
        var app = new App();
        app.InitializeComponent();
        app.Run();
    }
}