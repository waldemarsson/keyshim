using Google.Apis.Auth.OAuth2;
using Google.Cloud.SecretManager.V1;

// Parse ADC-style credentials offline; this runs the Newtonsoft-based auth path that warns under AOT.
var credential = CredentialFactory.FromJson<UserCredential>(
    """{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"token"}""");
Console.WriteLine($"gcp credential parsed: {credential.GetType().Name}");

// Network calls run only with "call"; client creation resolves ADC, so it is gated too.
if (args is ["call"])
{
    var client = await SecretManagerServiceClient.CreateAsync();
    var version = await client.AccessSecretVersionAsync(
        SecretVersionName.FromProjectSecretSecretVersion("example", "example", "latest"));
    Console.WriteLine(version.Payload.Data.Length);
}
Console.WriteLine("gcp ok");
