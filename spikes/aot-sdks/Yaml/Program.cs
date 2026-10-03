using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

// Reflection-based deserializer, the default YamlDotNet path.
var deserializer = new DeserializerBuilder()
    .WithNamingConvention(CamelCaseNamingConvention.Instance)
    .Build();
var config = deserializer.Deserialize<Config>("listen: 127.0.0.1:8899\nrules:\n  - host: api.github.com\n");
Console.WriteLine($"yaml ok: {config.Listen} {config.Rules[0].Host}");

public class Config
{
    public string Listen { get; set; } = "";
    public List<Rule> Rules { get; set; } = [];
}

public class Rule
{
    public string Host { get; set; } = "";
}
