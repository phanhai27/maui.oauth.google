namespace OAuthSample;

public partial class App : Application
{
    public App()
    {
        InitializeComponent();
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        var displayInfo = DeviceDisplay.Current.MainDisplayInfo;
        var width = 700;
        var height = 500;
        var centerX = (displayInfo.Width / displayInfo.Density - width) / 2;
        var centerY = (displayInfo.Height / displayInfo.Density - height) / 2;

        return new Window(new AppShell())
        {
            Width = width,
            Height = height,
            X = centerX,
            Y = centerY
        };
    }
}