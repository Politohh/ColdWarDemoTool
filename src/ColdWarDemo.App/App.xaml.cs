using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace ColdWarDemo.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        string? snapshot = Argument(e.Args, "--snapshot");
        string? demo = Argument(e.Args, "--open");
        string? scan = Argument(e.Args, "--scan");
        var window = new MainWindow(diagnosticMode: snapshot is not null);
        MainWindow = window;
        if (snapshot is not null)
        {
            window.Left = -20000;
            window.Top = -20000;
            window.ShowInTaskbar = false;
            window.ShowActivated = false;
            window.WindowStartupLocation = WindowStartupLocation.Manual;
        }
        window.Loaded += async (_, _) =>
        {
            if (demo is not null) await window.OpenDemoAsync(demo);
            if (scan is not null) await window.ScanAsync(int.Parse(scan));
            if (snapshot is not null)
            {
                await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
                window.UpdateLayout();
                var bitmap = new RenderTargetBitmap((int)window.Root.ActualWidth, (int)window.Root.ActualHeight,
                    96, 96, PixelFormats.Pbgra32);
                bitmap.Render(window.Root);
                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(bitmap));
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(snapshot))!);
                using (var output = File.Create(snapshot)) encoder.Save(output);
                File.WriteAllText(snapshot + ".json", JsonSerializer.Serialize(new
                {
                    width = bitmap.PixelWidth, height = bitmap.PixelHeight,
                    replayCount = window.ReplayCount, uiErrors = window.LastError,
                    selectedMap = window.SelectedMap, demos = window.ReplayDetails
                }, new JsonSerializerOptions { WriteIndented = true }));
                Shutdown();
            }
        };
        window.Show();
    }
    private static string? Argument(string[] args, string key)
    {
        int index = Array.IndexOf(args, key);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}
