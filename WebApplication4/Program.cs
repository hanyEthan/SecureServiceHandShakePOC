using ClassLibrary1.Utilities;

namespace WebApplication4
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                    webBuilder.ConfigureKestrel(config =>
                    {
                        config.UseMutualAuthentication();
                    });
                })
                .Build()
                .Run();
        }
    }
}
