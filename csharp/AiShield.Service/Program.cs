using AiShield.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "AiShield");
builder.Services.AddSingleton<BackendSupervisor>(sp =>
{
    var config = AiShield.Core.Config.ConfigLoader.Load();
    return new BackendSupervisor(sp.GetRequiredService<ILogger<BackendSupervisor>>(), config);
});
builder.Services.AddHostedService<ShieldWorker>();
var host = builder.Build();
host.Run();
