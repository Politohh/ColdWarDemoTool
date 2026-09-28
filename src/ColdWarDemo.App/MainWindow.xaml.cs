using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using ColdWarDemo.Core;
using Microsoft.Win32;

namespace ColdWarDemo.App;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<CapturedDemo> demos = [];
    private CancellationTokenSource? cancellation;
    private bool busy;
    private readonly bool diagnosticMode;
    private readonly string preferences = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ColdWarDemoTool", "settings.json");
    public int ReplayCount => demos.Count;
    public string? LastError { get; private set; }
    public string? SelectedMap => (ReplayList.SelectedItem as CapturedDemo)?.Metadata.Map;
    public object[] ReplayDetails => demos.Select(d => (object)new { d.Metadata, d.Source }).ToArray();

    public MainWindow(bool diagnosticMode = false)
    {
        this.diagnosticMode = diagnosticMode;
        InitializeComponent();
        ReplayList.ItemsSource = demos;
        FolderBox.Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Cold War Demos");
        try
        {
            if (File.Exists(preferences))
            {
                using JsonDocument document = JsonDocument.Parse(File.ReadAllText(preferences));
                string? saved = document.RootElement.GetProperty("saveFolder").GetString();
                if (!string.IsNullOrWhiteSpace(saved)) FolderBox.Text = Path.GetFullPath(saved);
            }
        }
        catch (Exception e) when (e is IOException or JsonException or ArgumentException or KeyNotFoundException) { }
        RefreshProcesses();
    }

    private void RefreshProcesses()
    {
        int? selected = (ProcessPicker.SelectedItem as GameProcess)?.Pid;
        var processes = GameProcess.Find();
        ProcessPicker.ItemsSource = processes;
        ProcessPicker.SelectedItem = processes.FirstOrDefault(p => p.Pid == selected) ?? processes.FirstOrDefault();
        FindButton.IsEnabled = !busy && ProcessPicker.SelectedItem is GameProcess;
        if (processes.Count == 0) Status("Cold War is not running. You can still open a saved demo.");
    }

    private async void Find_Click(object sender, RoutedEventArgs e)
    {
        if (ProcessPicker.SelectedItem is not GameProcess game) return;
        await ScanAsync(game.Pid);
    }

    public async Task ScanAsync(int pid)
    {
        LastError = null;
        demos.Clear();
        UpdateList();
        cancellation = new CancellationTokenSource();
        SetBusy(true);
        Status("Searching the loaded replay data…");
        var progress = new Progress<ScanProgress>(p =>
        {
            Status(p.Description);
            SearchProgress.Value = p.TotalRegions == 0 ? 0 : 100.0 * p.RegionsVisited / p.TotalRegions;
        });
        try
        {
            ScanResult result = await Task.Run(() => ReplayScanner.Scan(pid, progress, cancellation.Token,
                found: demo => Dispatcher.Invoke(() => AddDemo(demo))));
            string completion = result.Complete ? "Search complete" : "Search limit reached";
            Status(result.Demos.Count == 0
                ? "No complete demo found. Load a replay in Theater, pause it, then try again."
                : $"{completion} · {result.Demos.Count} demo(s) found in {result.Elapsed.TotalSeconds:0.0}s. Select the correct replay and save it.");
        }
        catch (OperationCanceledException) { Status($"Search stopped · {demos.Count} demo(s) available."); }
        catch (Exception ex) { ReportError(ex); }
        finally { cancellation.Dispose(); cancellation = null; SetBusy(false); }
    }

    private void AddDemo(CapturedDemo demo)
    {
        if (demos.Any(d => d.Metadata.Sha256 == demo.Metadata.Sha256)) return;
        demos.Add(demo);
        UpdateList();
        if (ReplayList.SelectedItem is null) ReplayList.SelectedIndex = 0;
    }

    private void UpdateList()
    {
        ListHeading.Text = demos.Count == 0 ? "DEMOS" : $"DEMOS · {demos.Count}";
        ListEmpty.Visibility = demos.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ReplayList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        CapturedDemo? demo = ReplayList.SelectedItem as CapturedDemo;
        DetailEmpty.Visibility = demo is null ? Visibility.Visible : Visibility.Collapsed;
        DetailPanel.Visibility = demo is null ? Visibility.Collapsed : Visibility.Visible;
        SaveButton.IsEnabled = demo is not null && !busy;
        if (demo is null) return;
        MapLabel.Text = demo.Metadata.DisplayMap;
        ModeLabel.Text = demo.Metadata.DisplayMode;
        DateLabel.Text = demo.Metadata.DisplayDate;
        DurationLabel.Text = demo.Metadata.DisplayDuration;
        SizeLabel.Text = demo.Metadata.DisplaySize;
        VersionLabel.Text = demo.Metadata.DataVersion.ToString();
        SourceLabel.Text = demo.SourceLabel;
        SourceHint.Text = demo.Source is not null ? "Two identical external reads. No hooks or game writes." : "Original file unchanged. Save creates a separate copy.";
    }

    public async Task OpenDemoAsync(string path)
    {
        LastError = null;
        SetBusy(true);
        Status("Opening and checking the demo…");
        try
        {
            CapturedDemo demo = await Task.Run(() => DemoStorage.Open(path));
            AddDemo(demo);
            ReplayList.SelectedItem = demos.First(d => d.Metadata.Sha256 == demo.Metadata.Sha256);
            Status($"Opened {Path.GetFileName(path)} · structure and compressed blocks validated.");
        }
        catch (Exception ex) { ReportError(ex); }
        finally { SetBusy(false); }
    }

    private async void Open_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Open a Cold War demo", Filter = "Cold War demos (*.demo)|*.demo|All files (*.*)|*.*", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) await OpenDemoAsync(dialog.FileName);
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        if (ReplayList.SelectedItem is not CapturedDemo demo) return;
        LastError = null;
        string folder = FolderBox.Text;
        bool metadata = MetadataCheck.IsChecked == true;
        SetBusy(true);
        Status("Saving the selected demo…");
        try
        {
            SaveResult result = await Task.Run(() => DemoStorage.Save(demo, folder, metadata));
            Status(result.MetadataWarning ?? $"Saved {Path.GetFileName(result.Path)} · file hash verified.");
            PersistFolder();
        }
        catch (Exception ex) { ReportError(ex); }
        finally { SetBusy(false); }
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose where to save demos", InitialDirectory = Directory.Exists(FolderBox.Text) ? FolderBox.Text : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) };
        if (dialog.ShowDialog(this) == true) { FolderBox.Text = dialog.FolderName; PersistFolder(); }
    }
    private void PersistFolder()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(preferences)!);
            File.WriteAllText(preferences, JsonSerializer.Serialize(new { saveFolder = FolderBox.Text }));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Status("Demo saved. The save-folder preference could not be stored."); }
    }
    private void ShowFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(FolderBox.Text);
            Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true, ArgumentList = { FolderBox.Text } });
        }
        catch (Exception ex) { ReportError(ex); }
    }
    private void Details_Click(object sender, RoutedEventArgs e)
    {
        if (ReplayList.SelectedItem is not CapturedDemo demo) return;
        Clipboard.SetText(JsonSerializer.Serialize(new
        {
            tool = "Cold War Demo Tool 0.1.0", metadata = demo.Metadata, source = demo.Source,
            validations = "Native envelope and all three LZ4 blocks checked. Native checksum and full frame interpretation not checked.",
            capture = "External read-only process handle. No hooks, injection, remote writes, or debugger attach."
        }, new JsonSerializerOptions { WriteIndented = true }));
        Status("Technical details copied.");
    }
    private void SetBusy(bool value)
    {
        busy = value;
        ProcessPicker.IsEnabled = RefreshButton.IsEnabled = OpenButton.IsEnabled = BrowseButton.IsEnabled = !value;
        MetadataCheck.IsEnabled = !value;
        FindButton.IsEnabled = !value && ProcessPicker.SelectedItem is GameProcess;
        SaveButton.IsEnabled = !value && ReplayList.SelectedItem is CapturedDemo;
        CancelButton.Visibility = value && cancellation is not null ? Visibility.Visible : Visibility.Collapsed;
        SearchProgress.Visibility = value && cancellation is not null ? Visibility.Visible : Visibility.Collapsed;
        if (value) SearchProgress.Value = 0;
    }
    private void Status(string text) => StatusLabel.Text = text;
    private void ReportError(Exception ex)
    {
        LastError = ex.Message;
        Status("Error: " + ex.Message);
        if (!diagnosticMode) MessageBox.Show(this, ex.Message, "Cold War Demo Tool", MessageBoxButton.OK, MessageBoxImage.Information);
    }
    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshProcesses();
    private void Cancel_Click(object sender, RoutedEventArgs e) => cancellation?.Cancel();
    private void Window_Closing(object? sender, CancelEventArgs e) => cancellation?.Cancel();
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not FrameworkElement element || element is Button || element.TemplatedParent is Button) return;
        if (e.ClickCount == 2) WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        else if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
}
