// The protected service core arrives in M2. Nothing installs this project yet.
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "AiShield");
builder.Build().Run();
