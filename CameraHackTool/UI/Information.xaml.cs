using System.Diagnostics;
using System.Reflection;
using System.Windows.Documents;
using System.Windows.Navigation;
using CameraHackTool.Util;

namespace CameraHackTool.UI;

public partial class Information
{
    public Information()
    {
        InitializeComponent();

        TextBlockInfo.Inlines.Clear();
        TextBlockInfo.Inlines.Add("XIVCameraHack v" + Assembly.GetExecutingAssembly().GetName().Version?.ToString(2) + ".\n");
        TextBlockInfo.Inlines.Add("Developed by Chipotle Ismylife.\n");
        TextBlockInfo.Inlines.Add("Modernized by Meowchestra");
        TextBlockInfo.Inlines.Add("\n");
        TextBlockInfo.Inlines.Add("Github: ");
        var ghlink = new Hyperlink
        {
            NavigateUri = new Uri("https://github.com/Meowchestra/XIVCameraHack")
        };
        ghlink.Inlines.Add("https://github.com/Meowchestra/XIVCameraHack");
        ghlink.RequestNavigate += Hyperlink_RequestNavigate;
        TextBlockInfo.Inlines.Add(ghlink);
        TextBlockInfo.Inlines.Add("\n");
        TextBlockInfo.Inlines.Add("Metadata (for nerds):\n");
        TextBlockInfo.Inlines.Add($"\tLocalRegion:\t{Metadata.Instance.LocalRegion}\n");
        TextBlockInfo.Inlines.Add($"\tLocalVersion:\t{Metadata.Instance.LocalVersion}\n");
        TextBlockInfo.Inlines.Add($"\tNewerVersion:\t{Metadata.Instance.NewerVersion}\n");
        TextBlockInfo.Inlines.Add($"\tDownloadURL:\t{Metadata.Instance.DownloadUrl}\n");
        TextBlockInfo.Inlines.Add($"\tCameraZoom:\tffxiv_dx11.exe+0x{Metadata.Instance.CameraZoom.Address:X} + 0x{Metadata.Instance.CameraZoom.Offset:X}\n");
        TextBlockInfo.Inlines.Add($"\tCameraFOV:\tffxiv_dx11.exe+0x{Metadata.Instance.CameraFov.Address:X} + 0x{Metadata.Instance.CameraFov.Offset:X}\n");
        TextBlockInfo.Inlines.Add($"\tCameraAngleX:\tffxiv_dx11.exe+0x{Metadata.Instance.CameraAngleX.Address:X} + 0x{Metadata.Instance.CameraAngleX.Offset:X}\n");
        TextBlockInfo.Inlines.Add($"\tCameraAngleY:\tffxiv_dx11.exe+0x{Metadata.Instance.CameraAngleY.Address:X} + 0x{Metadata.Instance.CameraAngleY.Offset:X}\n");
        TextBlockInfo.Inlines.Add($"\tNameOffset:\t{Metadata.Instance.PlayerNameOffset}\n");
        TextBlockInfo.Inlines.Add($"\tHeightOffset:\t{Metadata.Instance.CameraHeightOffset}\n");
        TextBlockInfo.Inlines.Add($"\tMetadataURL:\t{Metadata.Instance.MetadataUrl}\n");
    }

    private static void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        var psi = new ProcessStartInfo
        {
            FileName        = e.Uri.AbsoluteUri,
            UseShellExecute = true
        };
        Process.Start(psi);
        e.Handled = true;
    }
}