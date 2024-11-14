using System.Globalization;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Xml.Linq;

namespace CameraHackTool.Util;

public class Metadata
{
    public static Metadata Instance => Arbitur.Value;

    private static readonly Lazy<Metadata> Arbitur = new(() => new Metadata());

#if DEBUG
    public readonly string MetadataUrl = Path.Combine(Directory.GetParent(Environment.CurrentDirectory)?.Parent?.Parent?.Parent?.FullName!, "Resources/AddressAndOffsetMetadata.xml");
#else
        public string MetadataURL = "https://raw.githubusercontent.com/Meowchestra/XIVCameraHack/main/CameraHackTool/Resources/AddressAndOffsetMetadata.xml";
#endif

    public enum MetadataResult
    {
        Success,
        UpdateAvailable,
        RunningBeta,
        Failure
    }

    public enum GameRegion
    {
        LV = 0,
        KR = 1,
        CN = 2,
    }

    protected Metadata()
    {
        LocalVersion = Assembly.GetExecutingAssembly().GetName().Version;
    }

    public MetadataResult GrabApplicationMetadata()
    {
        try
        {
            var xmlf = XDocument.Load(MetadataUrl);
            var root = xmlf.Element("Root");

            foreach (var element in root?.Elements()!)
            {
                switch (element.Name.LocalName)
                {
                    case "AppVersion":
                        NewerVersion = new Version(element.Value);
                        break;
                    case "DownloadLink":
                        DownloadUrl = element.Value;
                        break;
                    case "AppMetadata":
                        foreach (var region in Enum.GetValues<GameRegion>())
                        {
                            var rs = region.ToString();
                            var cElem = element.Element(rs);
                            var oElem = cElem?.Element("Offsets");
                            var address = int.Parse(cElem?.Element("Address")?.Value!, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

                            _cameraZoomData[rs] = new MemoryAddressAndOffset(
                                address,
                                int.Parse(oElem?.Element("CameraZoom")?.Value!, NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                            );
                            _cameraFovData[rs] = new MemoryAddressAndOffset(
                                address,
                                int.Parse(oElem?.Element("CameraFOV")?.Value!, NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                            );
                            _cameraAngleXData[rs] = new MemoryAddressAndOffset(
                                address,
                                int.Parse(oElem?.Element("CameraAngleX")?.Value!, NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                            );
                            _cameraAngleYData[rs] = new MemoryAddressAndOffset(
                                address,
                                int.Parse(oElem?.Element("CameraAngleY")?.Value!, NumberStyles.HexNumber, CultureInfo.InvariantCulture)
                            );
                            _playerNameData[rs] = int.Parse(oElem?.Element("PlayerName")?.Value!, NumberStyles.Integer, CultureInfo.InvariantCulture).ToString();
                            _cameraHeightData[rs] = int.Parse(oElem?.Element("CameraHeight")?.Value!, NumberStyles.Integer, CultureInfo.InvariantCulture).ToString();
                        }
                        break;
                }
            }

            if (LocalVersion != null)
            {
                return LocalVersion.CompareTo(NewerVersion) switch
                {
                    // -1 means earlier than
                    -1 => MetadataResult.UpdateAvailable,
                    // 1 means later than
                    1 => MetadataResult.RunningBeta,
                    _ => MetadataResult.Success
                };
            }
        }
        catch (Exception e)
        {
            MessageBox.Show(
                "Unable to read offsets from server. Reason: " + e.Message + "\n\n" + e.StackTrace,
                "Error", MessageBoxButton.OK, MessageBoxImage.Error
            );
        }

        return MetadataResult.Failure;
    }

    private static bool IsValidGamePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        if (!Directory.Exists(path))
            return false;

        return File.Exists(Path.Combine(path, "game", "ffxivgame.ver")) && File.Exists(Path.Combine(path, "game", "ffxivgame.ver"));
    }

    public void InitializeToRegionFromGamePath(string? gamePath)
    {
        // find game region from static files
        LocalRegion = GameRegion.LV;
        if (gamePath != null)
        {
            var gameDirectory = Path.GetFullPath(Path.Combine(gamePath, "..", ".."));
            if (!IsValidGamePath(gameDirectory))
            {
                MessageBox.Show(
                    $"Please make sure ffxivgame.ver is in \n\n{gameDirectory}/game directory.",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error
                );
                return;
            }

            if (File.Exists(Path.Combine(gameDirectory, "FFXIVBoot.exe")) || File.Exists(Path.Combine(gameDirectory, "rail_files", "rail_game_identify.json")))
            {
                LocalRegion = GameRegion.CN;
            }
            else if (File.Exists(Path.Combine(gameDirectory, "boot", "FFXIV_Boot.exe")))
            {
                LocalRegion = GameRegion.KR;
            }
        }
    }

    public class MemoryAddressAndOffset(int addr, int off)
    {
        public readonly int Address = addr;
        public readonly int Offset = off;
    }

    public Version? LocalVersion { get; private set; }
    public Version? NewerVersion { get; private set; }
    public string? DownloadUrl { get; private set; }
    public MemoryAddressAndOffset CameraZoom => _cameraZoomData[LocalRegion.ToString()];
    public MemoryAddressAndOffset CameraFov => _cameraFovData[LocalRegion.ToString()];
    public MemoryAddressAndOffset CameraAngleX => _cameraAngleXData[LocalRegion.ToString()];
    public MemoryAddressAndOffset CameraAngleY => _cameraAngleYData[LocalRegion.ToString()];
    public string PlayerNameOffset => _playerNameData[LocalRegion.ToString()];
    public string CameraHeightOffset => _cameraHeightData[LocalRegion.ToString()];

    // region specific addresses
    public GameRegion LocalRegion;
    private readonly Dictionary<string, MemoryAddressAndOffset> _cameraZoomData = new();
    private readonly Dictionary<string, MemoryAddressAndOffset> _cameraFovData = new();
    private readonly Dictionary<string, MemoryAddressAndOffset> _cameraAngleXData = new();
    private readonly Dictionary<string, MemoryAddressAndOffset> _cameraAngleYData = new();
    private readonly Dictionary<string, string> _playerNameData = new();
    private readonly Dictionary<string, string> _cameraHeightData = new();
}