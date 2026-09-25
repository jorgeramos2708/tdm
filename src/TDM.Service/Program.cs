using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace TDM.Service;

public static class Program
{
    public static async Task Main(string[] args)
    {
        var builder = Host.CreateDefaultBuilder(args)
            .UseWindowsService(options => options.ServiceName = "TDM Service")
            .ConfigureServices(services => services.AddHostedService<TdmWorker>());
        await builder.Build().RunAsync().ConfigureAwait(false);
    }
}
