// Inert local fixture: these values are not credentials for any service.
public class ManagedInventoryFixture
{
    public const string Username = "alice_lab";
    public const string Password = "Fixture!9x";
    public const string EndpointUrl = "https://example.test/api";
    public const string PlaceholderSecret = "DEMO_ONLY_NOT_A_REAL_PASSWORD";
    public static string RuntimePassword;
    static ManagedInventoryFixture()
    {
        throw new System.InvalidOperationException("The metadata scan must not execute this constructor.");
    }
}
