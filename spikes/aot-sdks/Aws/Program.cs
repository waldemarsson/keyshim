using Amazon;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;

// Network calls run only with "call"; default run checks construction under AOT.
var client = new AmazonSecretsManagerClient(RegionEndpoint.EUNorth1);
if (args is ["call"])
{
    var response = await client.GetSecretValueAsync(new GetSecretValueRequest { SecretId = "example" });
    Console.WriteLine(response.Name);
}
Console.WriteLine("aws ok");
