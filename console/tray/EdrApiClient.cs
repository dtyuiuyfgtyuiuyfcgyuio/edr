using System.Net;
using System.Text.Json;

namespace EdrTray;

internal sealed class EdrApiClient : IDisposable
{
    private readonly HttpClient httpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(6)
    };

    public EdrApiClient(string baseUrl, string apiKey)
    {
        Configure(baseUrl, apiKey);
    }

    public Uri BaseAddress { get; private set; } = new("http://localhost:8080/");
    public string ApiKey { get; private set; } = string.Empty;

    public void Configure(string baseUrl, string apiKey)
    {
        if (!Uri.TryCreate(baseUrl.Trim(), UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException("控制台地址必须是有效的 HTTP 或 HTTPS 地址。", nameof(baseUrl));
        }

        var builder = new UriBuilder(uri)
        {
            Query = string.Empty,
            Fragment = string.Empty,
            Path = uri.AbsolutePath.TrimEnd('/') + "/"
        };

        BaseAddress = builder.Uri;
        ApiKey = apiKey.Trim();
    }

    public async Task<EndpointSnapshot> GetSnapshotAsync(CancellationToken cancellationToken)
    {
        var baseAddress = BaseAddress;
        var apiKey = ApiKey;

        using var statsRequest = CreateRequest(baseAddress, "api/stats", apiKey);
        using var alertsRequest = CreateRequest(baseAddress, "api/alerts?limit=50", apiKey);
        using var statsResponse = await httpClient.SendAsync(statsRequest, cancellationToken);

        ThrowForStatus(statsResponse.StatusCode);
        using var alertsResponse = await httpClient.SendAsync(alertsRequest, cancellationToken);
        ThrowForStatus(alertsResponse.StatusCode);

        try
        {
            await using var statsStream = await statsResponse.Content.ReadAsStreamAsync(cancellationToken);
            await using var alertsStream = await alertsResponse.Content.ReadAsStreamAsync(cancellationToken);
            using var statsDocument = await JsonDocument.ParseAsync(statsStream, cancellationToken: cancellationToken);
            using var alertsDocument = await JsonDocument.ParseAsync(alertsStream, cancellationToken: cancellationToken);

            var stats = ParseStats(statsDocument.RootElement);
            var alerts = ParseAlerts(alertsDocument.RootElement);
            return new EndpointSnapshot(stats, alerts, DateTimeOffset.Now);
        }
        catch (JsonException exception)
        {
            throw new EndpointApiException("控制台返回了无法识别的数据。", false, exception);
        }
    }

    public void Dispose()
    {
        httpClient.Dispose();
    }

    private static HttpRequestMessage CreateRequest(Uri baseAddress, string relativePath, string apiKey)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(baseAddress, relativePath));
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            request.Headers.TryAddWithoutValidation("X-API-Key", apiKey);
        }
        return request;
    }

    private static void ThrowForStatus(HttpStatusCode statusCode)
    {
        if (statusCode == HttpStatusCode.Unauthorized || statusCode == HttpStatusCode.Forbidden)
        {
            throw new EndpointApiException("需要有效的只读 API 密钥。", true);
        }
        if ((int)statusCode < 200 || (int)statusCode >= 300)
        {
            throw new EndpointApiException($"控制台请求失败（HTTP {(int)statusCode}）。", false);
        }
    }

    private static EndpointStats ParseStats(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException("Stats response is not an object.");
        }

        var bySeverity = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("bySeverity", out var severities) && severities.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in severities.EnumerateObject())
            {
                if (property.Value.TryGetInt32(out var count))
                {
                    bySeverity[property.Name] = count;
                }
            }
        }

        return new EndpointStats(
            ReadInt32(root, "total"),
            ReadInt32(root, "events"),
            ReadInt32(root, "processes"),
            bySeverity);
    }

    private static IReadOnlyList<EndpointAlert> ParseAlerts(JsonElement root)
    {
        JsonElement list;
        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("alerts", out var alertsProperty) &&
            alertsProperty.ValueKind == JsonValueKind.Array)
        {
            /* New shape: { total, alerts: [...] } */
            list = alertsProperty;
        }
        else if (root.ValueKind == JsonValueKind.Array)
        {
            /* Legacy shape: bare array */
            list = root;
        }
        else
        {
            throw new JsonException("Alerts response is not an array.");
        }

        var alerts = new List<EndpointAlert>();
        foreach (var item in list.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var eventElement = item.TryGetProperty("event", out var eventValue) &&
                eventValue.ValueKind == JsonValueKind.Object
                ? eventValue
                : default;
            var rawTimestamp = ReadString(item, "timestamp");
            DateTimeOffset.TryParse(rawTimestamp, out var timestamp);

            alerts.Add(new EndpointAlert(
                ReadString(item, "id"),
                ReadString(item, "rule"),
                ReadString(item, "severity"),
                timestamp,
                eventElement.ValueKind == JsonValueKind.Object ? ReadString(eventElement, "type") : string.Empty,
                FirstNonEmpty(eventElement, "image", "command_line", "output"),
                ReadString(item, "sourceId"),
                item.Clone()));
        }
        return alerts;
    }

    private static int ReadInt32(JsonElement value, string propertyName)
    {
        return value.TryGetProperty(propertyName, out var property) && property.TryGetInt32(out var result)
            ? result
            : 0;
    }

    private static string ReadString(JsonElement value, string propertyName)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(propertyName, out var property))
        {
            return string.Empty;
        }
        return property.ValueKind == JsonValueKind.String ? property.GetString() ?? string.Empty : property.ToString();
    }

    private static string FirstNonEmpty(JsonElement value, params string[] propertyNames)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            return string.Empty;
        }

        foreach (var propertyName in propertyNames)
        {
            var text = ReadString(value, propertyName);
            if (!string.IsNullOrWhiteSpace(text))
            {
                return text;
            }
        }
        return string.Empty;
    }
}

internal sealed class EndpointApiException : Exception
{
    public EndpointApiException(string message, bool authenticationRequired, Exception? innerException = null)
        : base(message, innerException)
    {
        AuthenticationRequired = authenticationRequired;
    }

    public bool AuthenticationRequired { get; }
}

internal sealed record EndpointStats(
    int Total,
    int Events,
    int Processes,
    IReadOnlyDictionary<string, int> BySeverity)
{
    public int SeverityCount(string severity)
    {
        return BySeverity.TryGetValue(severity, out var count) ? count : 0;
    }
}

internal sealed record EndpointAlert(
    string Id,
    string Rule,
    string Severity,
    DateTimeOffset Timestamp,
    string EventType,
    string Process,
    string SourceId,
    JsonElement Raw);

internal sealed record EndpointSnapshot(
    EndpointStats Stats,
    IReadOnlyList<EndpointAlert> Alerts,
    DateTimeOffset FetchedAt);
