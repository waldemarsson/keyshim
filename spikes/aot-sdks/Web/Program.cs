using System.Text.Json.Serialization;

// Minimal API with source-generated JSON, the AOT-supported ASP.NET Core shape.
var builder = WebApplication.CreateSlimBuilder(args);
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJson.Default));
builder.WebHost.UseUrls("http://127.0.0.1:0");

var app = builder.Build();
app.MapGet("/api/rules", () => new[] { new RuleDto("api.github.com", "github") });

if (args is ["serve"])
{
    app.Run();
}
else
{
    await app.StartAsync();
    await app.StopAsync();
    Console.WriteLine("web ok");
}

public record RuleDto(string Host, string Secret);

[JsonSerializable(typeof(RuleDto[]))]
internal partial class AppJson : JsonSerializerContext;
