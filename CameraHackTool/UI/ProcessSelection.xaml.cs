using System.Diagnostics;
using System.Windows;
using CameraHackTool.Util;

namespace CameraHackTool.UI;

public partial class ProcessSelection
{
    public List<ProcessModel?>? NewSelectedProcesses { get; private set; }

    private static List<ProcessModel?>? ProcessList { get; set; }

    public ProcessSelection()
    {
        InitializeComponent();

        ProcessList ??= [];

        {
            foreach (var proc in Process.GetProcesses())
            {
                var compared = ProcessList.AsParallel().Where(x => x is { Process: not null } && x.Process.Id == proc.Id).ToList();
                if (compared.Count == 0)
                {
                    if (string.Equals(proc.ProcessName, "ffxiv_dx11"))
                    {
                        Metadata.Instance.InitializeToRegionFromGamePath(proc.MainModule?.FileName);

                        var characterName = Memory.GetCharacterNameFromProcess(proc);
                        if (characterName.Length > 0)
                        {
                            ProcessList.Add(new ProcessModel
                            {
                                Name    = characterName,
                                Process = proc,
                                Hooked  = false,
                                Running = false
                            });
                        }
                    }
                }
            }
        }

        ListBoxProcesses.DataContext = ProcessList.Where(t => t is { Hooked: false });
    }

    private void Button_OpenAllProcess_Click(object sender, RoutedEventArgs e)
    {
        if (ProcessList != null) NewSelectedProcesses = ProcessList.Where(t => t is { Hooked: false }).ToList();
        DialogResult         = true;
    }

    private void Button_OpenThisProcess_Click(object sender, RoutedEventArgs e)
    {
        NewSelectedProcesses = [];
        if (ListBoxProcesses.SelectedItems.Count != 0)
        {
            foreach (var proc in ListBoxProcesses.SelectedItems)
            {
                var p = proc as ProcessModel;
                NewSelectedProcesses.Add(p);
            }
            DialogResult = true;
        }
    }
}

public class ProcessModel
{
    public string? Name { get; set; }
    public Process? Process { get; set; }
    public bool Hooked { get; set; }
    public bool Running { get; set; }

    public string GetFormattedName =>
        $"({Process?.Id ?? 0})\t| Active: {(Running ? "✓" : "✗")} | {Name}";
}