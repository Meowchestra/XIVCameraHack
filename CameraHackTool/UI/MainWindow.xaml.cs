using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using CameraHackTool.Util;

namespace CameraHackTool.UI;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow
{
    private List<ProcessModel?> AllSelectedProcesses { get; } = [];
    private ProcessModel? _highlightedProcess;
 
    public MainWindow()
    {
        InitializeComponent();

        // uncomment to test many processes
        //AllSelectedProcesses.Add(new ProcessModel { Name = "1", Running = false });
        //AllSelectedProcesses.Add(new ProcessModel { Name = "2", Running = false });
        //AllSelectedProcesses.Add(new ProcessModel { Name = "3", Running = false });
        //AllSelectedProcesses.Add(new ProcessModel { Name = "4", Running = false });
        //AllSelectedProcesses.Add(new ProcessModel { Name = "5", Running = false });
        //AllSelectedProcesses.Add(new ProcessModel { Name = "6", Running = false });
        //AllSelectedProcesses.Add(new ProcessModel { Name = "7", Running = false });
        //AllSelectedProcesses.Add(new ProcessModel { Name = "8", Running = false });
        //AllSelectedProcesses.Add(new ProcessModel { Name = "9", Running = false });
        //AllSelectedProcesses.Add(new ProcessModel { Name = "10", Running = false });

        // initialize singletons
        Memory.TheMainWindow = this;

        // initialize delegates
        Loaded += MainWindow_Loaded;

        // initialize variables
        ListBoxRunningProcesses.DataContext = AllSelectedProcesses;

        // set title to show version information
        Title = "XIVCameraHack v" + Assembly.GetExecutingAssembly().GetName().Version?.ToString(2);
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        var res = Metadata.Instance.GrabApplicationMetadata();
        switch (res)
        {
            case Metadata.MetadataResult.Failure:
                Debug.WriteLine("Something has gone terribly wrong");
                Application.Current.Shutdown();
                break;
            case Metadata.MetadataResult.RunningBeta:
                Title += " (Beta)";
                break;
            case Metadata.MetadataResult.UpdateAvailable:
                var opt = MessageBox.Show(
                    $"You are running version {Metadata.Instance.LocalVersion?.ToString(2)}.\n" +
                    $"Update {Metadata.Instance.NewerVersion?.ToString(2)} is available for download.\n\n" +
                    $"Go to the downloads page?\n\n",
                    "Update Available", MessageBoxButton.YesNoCancel
                );

                switch (opt)
                {
                    case MessageBoxResult.Yes:
                        Process.Start(new ProcessStartInfo { FileName = Metadata.Instance.DownloadUrl, UseShellExecute = true });
                        break;
                    case MessageBoxResult.Cancel:
                        Application.Current.Shutdown();
                        break;
                }
                break;
            case Metadata.MetadataResult.Success:
                break;
        }
    }

    private void Button_DoTheThing_Click(object sender, RoutedEventArgs e)
    {
        foreach (var proc in AllSelectedProcesses)
        {
            StartProcess(proc);
        }

        ListBoxRunningProcesses.Items.Refresh();
    }

    private void Button_LoadProcess_Click(object sender, RoutedEventArgs e)
    {
        var processSelection = new ProcessSelection
        {
            Top  = Top,
            Left = Left
        };
        var dialogResult = processSelection.ShowDialog();
        if (dialogResult == true)
        {
            if (processSelection.NewSelectedProcesses != null)
            {
                foreach (var selectedProcess in processSelection.NewSelectedProcesses.OfType<ProcessModel>())
                {
                    selectedProcess.Hooked = true;
                    AllSelectedProcesses.Add(selectedProcess);
                }

                ListBoxRunningProcesses.Items.Refresh();
            }
        }
    }

    private static void StartProcess(ProcessModel? proc)
    {
        if (proc is { Running: false })
        {
            Memory.RunCameraHack(proc.Process);
            proc.Running = true;
        }
    }

    private static void StopProcess(ProcessModel? proc)
    {
        if (proc is { Running: true })
        {
            Memory.StopCameraHack(proc.Process);
            proc.Running = false;
        }
    }

    private void RemoveProcess(ProcessModel? proc)
    {
        try
        {
            StopProcess(proc);
            if (proc != null)
            {
                proc.Hooked = false;
                AllSelectedProcesses.Remove(
                    AllSelectedProcesses.Where(x => x is { Process: not null } && proc.Process != null && x.Process.Id == proc.Process.Id).ToList()[0]);
            }

            proc = null;
            ListBoxRunningProcesses.Items.Refresh();
        }
        catch (Exception e)
        {
            MessageBox.Show(
                "Something FUBAR is happening. Reason: " + e.Message + "\n\n" + e.StackTrace,
                "Error", MessageBoxButton.OK, MessageBoxImage.Error
            );
        }
    }

    public void RemoveProcessFromId(int pid)
    {
        Dispatcher.Invoke(DispatcherPriority.Normal, new Action(() => {
            var selectedModel = AllSelectedProcesses.Where(x => x is { Process: not null } && x.Process.Id == pid).ToList()[0];
            RemoveProcess(selectedModel);
        }));
    }

    private void Button_StopProcess_Click(object sender, RoutedEventArgs e)
    {
        if (_highlightedProcess != null)
        {
            StopProcess(_highlightedProcess);
            ListBoxRunningProcesses.Items.Refresh();
        }
    }

    private void Button_RemoveProcess_Click(object sender, RoutedEventArgs e)
    {
        if (_highlightedProcess != null)
        {
            RemoveProcess(_highlightedProcess);
            ListBoxRunningProcesses.Items.Refresh();
        }
    }

    private void ListBox_RunningProcesses_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.AddedItems.Count == 1)
        {
            _highlightedProcess = e.AddedItems[0] as ProcessModel;
        }
    }

    private void Button_StopAllProcesses_Click(object sender, RoutedEventArgs e)
    {
        foreach (var proc in AllSelectedProcesses)
        {
            StopProcess(proc);
        }

        ListBoxRunningProcesses.Items.Refresh();
    }

    private void Window_Closing(object sender, CancelEventArgs e)
    {
        foreach (var proc in AllSelectedProcesses)
        {
            StopProcess(proc);
        }

        ListBoxRunningProcesses.Items.Refresh();
    }

    private void ListBox_RunningProcesses_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if ((sender as ListBox)?.SelectedItem != null)
        {
            _highlightedProcess = (sender as ListBox)?.SelectedItem as ProcessModel;
            if (_highlightedProcess is { Running: true })
            {
                StopProcess(_highlightedProcess);
            }
            else
            {
                StartProcess(_highlightedProcess);
            }

            ListBoxRunningProcesses.Items.Refresh();
        }
    }

    private void Button_Info_Click(object sender, RoutedEventArgs e)
    {
        var processSelection = new Information
        {
            Top  = Top,
            Left = Left
        };
        var dialogResult = processSelection.ShowDialog();
        if (dialogResult == true)
        {
            // ???
        }
    }
}