using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

// Network calls run only with "call"; default run checks construction under AOT.
var client = new SecretClient(new Uri("https://example.vault.azure.net"), new DefaultAzureCredential());
if (args is ["call"])
{
    var secret = await client.GetSecretAsync("example");
    Console.WriteLine(secret.Value.Name);
}
Console.WriteLine("azure ok");
