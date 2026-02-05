using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

var builder = WebApplication.CreateBuilder(args);

// ✅ Render/Linux hay bị inotify limit => tắt reloadOnChange để tránh Exit 139
builder.Host.ConfigureAppConfiguration((ctx, cfg) =>
{
    cfg.Sources.Clear();
    cfg.AddJsonFile("appsettings.json", optional: true, reloadOnChange: false);
    cfg.AddJsonFile($"appsettings.{ctx.HostingEnvironment.EnvironmentName}.json", optional: true, reloadOnChange: false);
    cfg.AddEnvironmentVariables();

    if (ctx.HostingEnvironment.IsDevelopment())
        cfg.AddUserSecrets<Program>(optional: true);
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddMemoryCache();

builder.Services.AddHttpClient("coze", c => c.Timeout = TimeSpan.FromSeconds(25));
builder.Services.AddHttpClient("fchat", c => c.Timeout = TimeSpan.FromSeconds(15));

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapGet("/", () => Results.Ok(new { ok = true }));
app.MapGet("/health", () => Results.Ok(new { ok = true }));

app.MapPost("/webhook/fchat", HandleFChatAsync);
app.MapPost("/webhook/fpt", HandleFptAsync).WithName("FptWebhook");

app.Run();

static async Task<IResult> HandleFChatAsync(
    HttpRequest request,
    IHttpClientFactory httpClientFactory,
    IConfiguration config,
    IMemoryCache cache,
    ILogger<Program> log)
{
    var trace = request.HttpContext.TraceIdentifier;
    var ct = request.HttpContext.RequestAborted;

    // ✅ 0) BẮT BUỘC api_key trên query (sai/thiếu => 401)
    if (!TryAuthorizeQueryApiKey(request, config, "Security:FChatApiKey", log, trace, out var authFail))
        return authFail!;

    // ✅ 0b) Optional: header secret (nếu bạn cấu hình FChat gọi được header)
    if (!TryAuthorizeHeaderSecret(request, config["FChat:WebhookSecret"], "X-Webhook-Secret", log, trace, out var secFail))
        return secFail!;

    // 1) Read body
    var raw = await new StreamReader(request.Body, Encoding.UTF8).ReadToEndAsync(ct);
    if (string.IsNullOrWhiteSpace(raw))
    {
        log.LogInformation("[FCHAT] trace={Trace} empty body", trace);
        return Results.Ok(new { ok = true });
    }

    // 2) Parse payload
    if (!TryParseFChatPayload(raw, out var email, out var text))
    {
        log.LogWarning("[FCHAT] trace={Trace} invalid payload", trace);
        return Results.Ok(new { ok = true });
    }

    log.LogInformation("[FCHAT] trace={Trace} emailHash={EmailHash} email={EmailMasked} textLen={Len} textPreview={Preview}",
        trace, Sha256Short(email), MaskEmail(email), text.Length, Preview(text));

    // 3) Cache conversation_id theo email
    var cacheKey = $"fchat:cid:{email.Trim().ToLowerInvariant()}";
    var conversationId = cache.TryGetValue(cacheKey, out string? cid) ? cid : null;

    // 4) Call Coze
    var (ok, answer, newCid, err) = await AskCozeAsync(
        httpClientFactory, config, log,
        userId: email,
        text: text,
        conversationId: conversationId,
        ct: ct);

    if (!ok)
    {
        log.LogWarning("[FCHAT] trace={Trace} coze failed: {Err}", trace, Preview(err, 300));
        answer = "Hệ thống đang bận hoặc cấu hình Coze chưa đúng. Vui lòng thử lại sau.";
    }

    if (!string.IsNullOrWhiteSpace(newCid))
    {
        cache.Set(cacheKey, newCid, new MemoryCacheEntryOptions
        {
            SlidingExpiration = TimeSpan.FromHours(12)
        });
    }

    // 5) Send back to FChat
    var baseUrl = config["FChat:BaseUrl"] ?? "https://alerts.soc.fpt.net/webhooks";
    var token = config["FChat:Token"];

    if (string.IsNullOrWhiteSpace(token))
    {
        log.LogError("[FCHAT] trace={Trace} missing FChat:Token", trace);
        return Results.Ok(new { ok = true });
    }

    var sendUrl = $"{baseUrl.TrimEnd('/')}/{token}/fchat";
    var sendBody = new { email, text = answer };

    var fchat = httpClientFactory.CreateClient("fchat");
    using var sendResp = await fchat.PostAsync(
        sendUrl,
        new StringContent(JsonSerializer.Serialize(sendBody), Encoding.UTF8, "application/json"),
        ct);

    log.LogInformation("[FCHAT] trace={Trace} sendStatus={Status} sendUrlMasked={Masked}",
        trace, (int)sendResp.StatusCode, $"{baseUrl.TrimEnd('/')}/{MaskToken(token)}/fchat");

    return Results.Ok(new { ok = true });
}

static async Task<IResult> HandleFptAsync(
    HttpRequest request,
    IHttpClientFactory httpClientFactory,
    IConfiguration config,
    IMemoryCache cache,
    ILogger<Program> log)
{
    var trace = request.HttpContext.TraceIdentifier;
    var ct = request.HttpContext.RequestAborted;

    if (!TryAuthorizeHeaderSecret(request, config["Fpt:WebhookSecret"], "X-Webhook-Secret", log, trace, out var fail))
        return fail!;

    var raw = await new StreamReader(request.Body, Encoding.UTF8).ReadToEndAsync(ct);
    if (string.IsNullOrWhiteSpace(raw))
    {
        return Results.Json(new
        {
            messages = new[] { new { type = "text", content = new { text = "Body rỗng." } } }
        });
    }

    using var doc = JsonDocument.Parse(raw);
    var root = doc.RootElement;

    static string GetString(JsonElement r, params string[] keys)
    {
        foreach (var k in keys)
            if (r.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String)
            {
                var s = v.GetString();
                if (!string.IsNullOrWhiteSpace(s)) return s!;
            }
        return "";
    }

    var senderId = GetString(root, "sender_id", "senderId", "user_id", "userId");
    if (string.IsNullOrWhiteSpace(senderId)) senderId = "anonymous";

    var text = GetString(root, "sender_input", "text", "message", "query");
    var conversationId = GetString(root, "coze_conversation_id", "conversation_id");

    if (string.IsNullOrWhiteSpace(text))
    {
        return Results.Json(new
        {
            messages = new[] { new { type = "text", content = new { text = "Bạn vui lòng nhập nội dung câu hỏi." } } }
        });
    }

    if (string.IsNullOrWhiteSpace(conversationId))
    {
        var key = $"fpt:cid:{senderId}";
        if (cache.TryGetValue(key, out string? cachedCid)) conversationId = cachedCid;
    }

    log.LogInformation("[FPT] trace={Trace} senderHash={SenderHash} textLen={Len} textPreview={Preview} cidExists={HasCid}",
        trace, Sha256Short(senderId), text.Length, Preview(text), !string.IsNullOrWhiteSpace(conversationId));

    var (ok, answer, newCid, err) = await AskCozeAsync(
        httpClientFactory, config, log,
        userId: senderId,
        text: text,
        conversationId: conversationId,
        ct: ct);

    if (!ok)
    {
        log.LogWarning("[FPT] trace={Trace} coze failed: {Err}", trace, Preview(err, 300));
        answer = "Hệ thống đang bận hoặc cấu hình Coze chưa đúng. Vui lòng thử lại sau.";
    }

    if (!string.IsNullOrWhiteSpace(newCid))
    {
        cache.Set($"fpt:cid:{senderId}", newCid, new MemoryCacheEntryOptions
        {
            SlidingExpiration = TimeSpan.FromHours(12)
        });
    }

    return Results.Json(new
    {
        set_attributes = new { coze_conversation_id = newCid ?? "" },
        messages = new[] { new { type = "text", content = new { text = answer } } }
    });
}

// ======================= AUTH HELPERS =======================

static bool TryAuthorizeQueryApiKey(
    HttpRequest request,
    IConfiguration config,
    string configPath,
    ILogger log,
    string trace,
    out IResult? fail)
{
    // Render env: Security__FChatApiKey  => config["Security:FChatApiKey"]
    var expected = config[configPath];

    // ✅ Không có cấu hình => coi là lỗi cấu hình (500) để bạn biết mà sửa
    if (string.IsNullOrWhiteSpace(expected))
    {
        log.LogError("[AUTH] trace={Trace} missing config {ConfigPath}", trace, configPath);
        fail = Results.Problem($"Missing config: {configPath}");
        return false;
    }

    if (!request.Query.TryGetValue("api_key", out StringValues provided) || StringValues.IsNullOrEmpty(provided))
    {
        log.LogWarning("[AUTH] trace={Trace} missing api_key", trace);
        fail = Results.Unauthorized();
        return false;
    }

    if (!FixedTimeEqualsUtf8(expected, provided.ToString()))
    {
        log.LogWarning("[AUTH] trace={Trace} invalid api_key (providedHash={Hash})", trace, Sha256Short(provided.ToString()));
        fail = Results.Unauthorized();
        return false;
    }

    fail = null;
    return true;
}

static bool TryAuthorizeHeaderSecret(
    HttpRequest request,
    string? expected,
    string headerName,
    ILogger log,
    string trace,
    out IResult? fail)
{
    if (string.IsNullOrWhiteSpace(expected))
    {
        fail = null;
        return true; // không cấu hình => bỏ qua
    }

    if (!request.Headers.TryGetValue(headerName, out var got) || StringValues.IsNullOrEmpty(got))
    {
        log.LogWarning("[AUTH] trace={Trace} missing header {Header}", trace, headerName);
        fail = Results.Unauthorized();
        return false;
    }

    if (!FixedTimeEqualsUtf8(expected, got.ToString()))
    {
        log.LogWarning("[AUTH] trace={Trace} invalid header {Header}", trace, headerName);
        fail = Results.Unauthorized();
        return false;
    }

    fail = null;
    return true;
}

static bool FixedTimeEqualsUtf8(string a, string b)
{
    var ab = Encoding.UTF8.GetBytes(a);
    var bb = Encoding.UTF8.GetBytes(b);
    return ab.Length == bb.Length && CryptographicOperations.FixedTimeEquals(ab, bb);
}

// ======================= PAYLOAD PARSER =======================

static bool TryParseFChatPayload(string raw, out string email, out string text)
{
    email = "";
    text = "";

    using var doc = JsonDocument.Parse(raw);
    var root = doc.RootElement;

    if (!root.TryGetProperty("message", out var msg) || msg.ValueKind != JsonValueKind.Object) return false;
    if (!msg.TryGetProperty("text", out var t) || t.ValueKind != JsonValueKind.String) return false;
    if (!msg.TryGetProperty("user", out var user) || user.ValueKind != JsonValueKind.Object) return false;
    if (!user.TryGetProperty("email", out var e) || e.ValueKind != JsonValueKind.String) return false;

    text = t.GetString() ?? "";
    email = e.GetString() ?? "";

    return !(string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(text));
}

// ======================= COZE CALLER =======================

static async Task<(bool Ok, string Answer, string? NewConversationId, string? Error)>
AskCozeAsync(
    IHttpClientFactory httpClientFactory,
    IConfiguration config,
    ILogger log,
    string userId,
    string text,
    string? conversationId,
    CancellationToken ct)
{
    var cozeBaseUrl = config["Coze:BaseUrl"] ?? "https://api.coze.com";
    var cozePat = config["Coze:Pat"];
    var cozeBotId = config["Coze:BotId"];

    if (string.IsNullOrWhiteSpace(cozePat) || string.IsNullOrWhiteSpace(cozeBotId))
        return (false, "", null, "Missing Coze config (Pat/BotId)");

    var url = $"{cozeBaseUrl.TrimEnd('/')}/v3/chat";
    if (!string.IsNullOrWhiteSpace(conversationId))
        url += $"?conversation_id={Uri.EscapeDataString(conversationId)}";

    var body = new
    {
        bot_id = cozeBotId,
        user_id = userId,
        stream = true,
        auto_save_history = true,
        additional_messages = new[]
        {
            new { role = "user", content = text, content_type = "text" }
        }
    };

    var http = httpClientFactory.CreateClient("coze");
    using var reqMsg = new HttpRequestMessage(HttpMethod.Post, url);
    reqMsg.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
    reqMsg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cozePat);
    reqMsg.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

    using var resp = await http.SendAsync(reqMsg, HttpCompletionOption.ResponseHeadersRead, ct);

    var contentType = resp.Content?.Headers.ContentType?.ToString() ?? "";
    log.LogInformation("[COZE] status={Status} contentType={ContentType}", (int)resp.StatusCode, contentType);

    if (!resp.IsSuccessStatusCode || resp.Content == null)
    {
        var err = resp.Content == null ? "(no content)" : await resp.Content.ReadAsStringAsync(ct);
        return (false, "", null, $"Coze HTTP {(int)resp.StatusCode}: {Preview(err, 300)}");
    }

    var mediaType = resp.Content.Headers.ContentType?.MediaType ?? "";
    if (!mediaType.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase))
    {
        var json = await resp.Content.ReadAsStringAsync(ct);
        return (false, "", null, $"Coze JSON (non-stream): {Preview(json, 300)}");
    }

    // SSE parse
    string currentEvent = "";
    var dataLines = new List<string>();
    bool done = false;

    string? newConversationId = conversationId;
    var answerDelta = new StringBuilder();
    string completedAnswer = "";

    static string ExtractAssistantText(JsonElement r)
    {
        if (r.TryGetProperty("content", out var c) && c.ValueKind == JsonValueKind.String)
            return c.GetString() ?? "";

        if (r.TryGetProperty("delta", out var d) && d.ValueKind == JsonValueKind.Object &&
            d.TryGetProperty("content", out var dc) && dc.ValueKind == JsonValueKind.String)
            return dc.GetString() ?? "";

        if (r.TryGetProperty("content", out var co) && co.ValueKind == JsonValueKind.Object &&
            co.TryGetProperty("text", out var t) && t.ValueKind == JsonValueKind.String)
            return t.GetString() ?? "";

        return "";
    }

    void Dispatch()
    {
        if (string.IsNullOrWhiteSpace(currentEvent)) { dataLines.Clear(); return; }

        var dataStr = string.Join("\n", dataLines).Trim();

        if (currentEvent == "done")
        {
            if (dataStr == "[DONE]" || dataStr == "\"[DONE]\"") done = true;
            currentEvent = "";
            dataLines.Clear();
            return;
        }

        if (string.IsNullOrWhiteSpace(dataStr))
        {
            currentEvent = "";
            dataLines.Clear();
            return;
        }

        try
        {
            using var d = JsonDocument.Parse(dataStr);
            var r = d.RootElement;

            if (currentEvent == "conversation.chat.created" &&
                r.TryGetProperty("conversation_id", out var cid) &&
                cid.ValueKind == JsonValueKind.String)
            {
                newConversationId = cid.GetString() ?? newConversationId;
            }

            if ((currentEvent == "conversation.message.delta" || currentEvent == "conversation.message.completed") &&
                r.TryGetProperty("role", out var role) && role.GetString() == "assistant" &&
                r.TryGetProperty("type", out var type) && type.GetString() == "answer")
            {
                var s = ExtractAssistantText(r);
                if (!string.IsNullOrWhiteSpace(s))
                {
                    if (currentEvent == "conversation.message.delta") answerDelta.Append(s);
                    else completedAnswer = s;
                }
            }
        }
        catch { }

        currentEvent = "";
        dataLines.Clear();
    }

    await using var cozeStream = await resp.Content.ReadAsStreamAsync(ct);
    using var sr = new StreamReader(cozeStream);

    while (!ct.IsCancellationRequested)
    {
        var line = await sr.ReadLineAsync();
        if (line == null) break;

        if (line.Length == 0) { Dispatch(); if (done) break; continue; }
        if (line.StartsWith("event:", StringComparison.OrdinalIgnoreCase))
        {
            currentEvent = line["event:".Length..].Trim();
            continue;
        }
        if (line.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            dataLines.Add(line["data:".Length..].Trim());
            continue;
        }
    }

    Dispatch();

    var answer = !string.IsNullOrWhiteSpace(completedAnswer)
        ? completedAnswer.Trim()
        : answerDelta.ToString().Trim();

    return (true, answer, newConversationId, null);
}

// ======================= LOG HELPERS =======================

static string Preview(string? s, int max = 160)
{
    if (string.IsNullOrEmpty(s)) return "";
    s = s.Replace("\r", " ").Replace("\n", " ");
    return s.Length <= max ? s : s[..max] + "...";
}
static string MaskToken(string? token)
{
    if (string.IsNullOrWhiteSpace(token)) return "";
    if (token.Length <= 8) return "********";
    return token[..4] + "****" + token[^4..];
}
static string MaskEmail(string? email)
{
    if (string.IsNullOrWhiteSpace(email)) return "";
    var at = email.IndexOf('@');
    if (at <= 1) return "***" + (at >= 0 ? email[at..] : "");
    var name = email[..at];
    var domain = email[at..];
    var shown = name.Length <= 3 ? name[..1] : name[..2];
    return $"{shown}***{domain}";
}
static string Sha256Short(string? s)
{
    if (string.IsNullOrWhiteSpace(s)) return "";
    using var sha = SHA256.Create();
    var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
    return Convert.ToHexString(bytes)[..10].ToLowerInvariant();
}

public partial class Program { }
