using Microsoft.Extensions.Caching.Memory;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddMemoryCache();

builder.Services.AddHttpClient("coze", client =>
{
    client.Timeout = TimeSpan.FromSeconds(25);
});

builder.Services.AddHttpClient("fchat", client =>
{
    client.Timeout = TimeSpan.FromSeconds(15);
});

var app = builder.Build();
app.UseSwagger();
app.UseSwaggerUI();

app.MapGet("/", () => Results.Ok(new { ok = true })); // tránh GET / 404 trên ngrok/Render
app.MapGet("/health", () => Results.Ok(new { ok = true }));

// -------------------------
// Helpers (production-safe)
// -------------------------
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
    return Convert.ToHexString(bytes)[..10].ToLowerInvariant(); // 10 chars đủ để trace
}

static bool VerifySecret(HttpRequest req, string? expected, string headerName, ILogger log)
{
    if (string.IsNullOrWhiteSpace(expected))
        return true; // không cấu hình => bỏ qua

    if (!req.Headers.TryGetValue(headerName, out var got) || got.ToString() != expected)
    {
        log.LogWarning("Unauthorized: missing/invalid {HeaderName}", headerName);
        return false;
    }
    return true;
}

// -------------------------
// Coze caller (SSE + JSON)
// -------------------------
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

    var mediaType = resp.Content?.Headers.ContentType?.MediaType ?? "";
    log.LogInformation("Coze response: status={Status} contentType={ContentType}",
        (int)resp.StatusCode, resp.Content?.Headers.ContentType?.ToString());

    if (!resp.IsSuccessStatusCode || resp.Content == null)
    {
        var err = resp.Content == null ? "(no content)" : await resp.Content.ReadAsStringAsync(ct);
        return (false, "", null, $"Coze HTTP {(int)resp.StatusCode}: {Preview(err, 300)}");
    }

    // Nếu Coze trả JSON (thường là lỗi auth/token/botId/permission...)
    if (!mediaType.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase))
    {
        var json = await resp.Content.ReadAsStringAsync(ct);
        // KHÔNG log full JSON (có thể dài). Chỉ preview.
        log.LogWarning("Coze JSON (non-stream) preview={JsonPreview}", Preview(json, 300));
        return (false, "", null, $"Coze returned JSON (non-stream): {Preview(json, 300)}");
    }

    // ---------- SSE parser ----------
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

        if (r.TryGetProperty("delta", out var d) && d.ValueKind == JsonValueKind.Object)
        {
            if (d.TryGetProperty("content", out var dc) && dc.ValueKind == JsonValueKind.String)
                return dc.GetString() ?? "";
        }

        if (r.TryGetProperty("content", out var co) && co.ValueKind == JsonValueKind.Object)
        {
            if (co.TryGetProperty("text", out var t) && t.ValueKind == JsonValueKind.String)
                return t.GetString() ?? "";
        }

        return "";
    }

    void Dispatch()
    {
        if (string.IsNullOrWhiteSpace(currentEvent))
        {
            dataLines.Clear();
            return;
        }

        var dataStr = string.Join("\n", dataLines).Trim();

        if (currentEvent == "done")
        {
            if (dataStr == "[DONE]" || dataStr == "\"[DONE]\"")
                done = true;

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

            if (currentEvent == "conversation.chat.created")
            {
                if (r.TryGetProperty("conversation_id", out var cid) && cid.ValueKind == JsonValueKind.String)
                    newConversationId = cid.GetString() ?? newConversationId;
            }

            if ((currentEvent == "conversation.message.delta" || currentEvent == "conversation.message.completed") &&
                r.TryGetProperty("role", out var role) && role.GetString() == "assistant" &&
                r.TryGetProperty("type", out var type) && type.GetString() == "answer")
            {
                var s = ExtractAssistantText(r);
                if (!string.IsNullOrWhiteSpace(s))
                {
                    if (currentEvent == "conversation.message.delta")
                        answerDelta.Append(s);
                    else
                        completedAnswer = s;
                }
            }
        }
        catch
        {
            // ignore parse errors
        }

        currentEvent = "";
        dataLines.Clear();
    }

    await using var cozeStream = await resp.Content.ReadAsStreamAsync(ct);
    using var sr = new StreamReader(cozeStream);

    while (!sr.EndOfStream && !ct.IsCancellationRequested)
    {
        var line = await sr.ReadLineAsync();
        if (line == null) break;

        // production: không log raw SSE line-by-line để tránh spam log
        if (line.Length == 0)
        {
            Dispatch();
            if (done) break;
            continue;
        }

        if (line.StartsWith("event:"))
        {
            currentEvent = line["event:".Length..].Trim();
            continue;
        }

        if (line.StartsWith("data:"))
        {
            dataLines.Add(line["data:".Length..].Trim());
            continue;
        }
    }

    Dispatch();

    var answer = !string.IsNullOrWhiteSpace(completedAnswer)
        ? completedAnswer.Trim()
        : answerDelta.ToString().Trim();

    if (string.IsNullOrWhiteSpace(answer))
        answer = "";

    return (true, answer, newConversationId, null);
}

// =====================================
// 1) Webhook FChat -> Coze -> FChat send
// =====================================
app.MapPost("/webhook/fchat", async (
    HttpRequest request,
    IHttpClientFactory httpClientFactory,
    IConfiguration config,
    IMemoryCache cache,
    ILogger<Program> log) =>
{
    var trace = request.HttpContext.TraceIdentifier;

    // (1) Verify secret (nếu có cấu hình)
    var expectedFchatSecret = config["FChat:WebhookSecret"];
    if (!VerifySecret(request, expectedFchatSecret, "X-Webhook-Secret", log))
        return Results.Unauthorized();

    // (2) Read body (không log raw)
    var raw = await new StreamReader(request.Body, Encoding.UTF8).ReadToEndAsync();
    if (string.IsNullOrWhiteSpace(raw))
    {
        log.LogInformation("[FCHAT] trace={Trace} empty body", trace);
        return Results.Ok(new { ok = true });
    }

    // (3) Parse JSON: message.text + message.user.email
    string text = "";
    string email = "";

    try
    {
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;

        if (root.TryGetProperty("message", out var msg) && msg.ValueKind == JsonValueKind.Object)
        {
            if (msg.TryGetProperty("text", out var t) && t.ValueKind == JsonValueKind.String)
                text = t.GetString() ?? "";

            if (msg.TryGetProperty("user", out var user) && user.ValueKind == JsonValueKind.Object)
            {
                if (user.TryGetProperty("email", out var e) && e.ValueKind == JsonValueKind.String)
                    email = e.GetString() ?? "";
            }
        }
    }
    catch (Exception ex)
    {
        log.LogWarning(ex, "[FCHAT] trace={Trace} invalid json", trace);
        return Results.Ok(new { ok = true });
    }

    // (4) Production log (mask email, preview text)
    log.LogInformation("[FCHAT] trace={Trace} emailHash={EmailHash} email={EmailMasked} textLen={Len} textPreview={Preview}",
        trace,
        Sha256Short(email),
        MaskEmail(email),
        text?.Length ?? 0,
        Preview(text));

    if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(text))
    {
        log.LogWarning("[FCHAT] trace={Trace} missing email/text", trace);
        return Results.Ok(new { ok = true });
    }

    // (5) Cache conversation_id theo email
    var cacheKey = $"fchat:cid:{email.Trim().ToLowerInvariant()}";
    var conversationId = cache.TryGetValue(cacheKey, out string? cid) ? cid : "";

    // (6) Call Coze
    var ct = request.HttpContext.RequestAborted;
    log.LogInformation("[FCHAT] trace={Trace} calling coze... (cidExists={CidExists})", trace, !string.IsNullOrWhiteSpace(conversationId));

    var (ok, answer, newCid, err) = await AskCozeAsync(
        httpClientFactory,
        config,
        log,
        userId: email,               // dùng email làm user_id cho dễ ổn định
        text: text,
        conversationId: conversationId,
        ct: ct);

    if (!ok)
    {
        // Không log token. Chỉ log lỗi preview.
        log.LogWarning("[FCHAT] trace={Trace} coze failed: {Err}", trace, Preview(err, 300));
        answer = "Hệ thống đang bận hoặc cấu hình Coze chưa đúng. Vui lòng thử lại sau.";
    }

    // update cache conversation id nếu có
    if (!string.IsNullOrWhiteSpace(newCid))
    {
        cache.Set(cacheKey, newCid, new MemoryCacheEntryOptions
        {
            SlidingExpiration = TimeSpan.FromHours(12)
        });
    }

    log.LogInformation("[FCHAT] trace={Trace} cozeAnswerLen={Len} cozeAnswerPreview={Preview} newCidExists={NewCidExists}",
        trace, answer.Length, Preview(answer), !string.IsNullOrWhiteSpace(newCid));

    // (7) Send back to FChat
    var baseUrl = config["FChat:BaseUrl"] ?? "https://alerts.soc.fpt.net/webhooks";
    var token = config["FChat:Token"];
    if (string.IsNullOrWhiteSpace(token))
    {
        log.LogError("[FCHAT] trace={Trace} missing FChat:Token", trace);
        return Results.Ok(new { ok = true });
    }

    var sendUrl = $"{baseUrl.TrimEnd('/')}/{token}/fchat";
    var sendBody = new { email = email, text = answer };

    var fchat = httpClientFactory.CreateClient("fchat");
    var sendResp = await fchat.PostAsync(
        sendUrl,
        new StringContent(JsonSerializer.Serialize(sendBody), Encoding.UTF8, "application/json"),
        ct);

    log.LogInformation("[FCHAT] trace={Trace} sendStatus={Status} sendUrlMasked={Url}",
        trace, (int)sendResp.StatusCode, $"{baseUrl.TrimEnd('/')}/{MaskToken(token)}/fchat");

    return Results.Ok(new { ok = true });
});

// =====================================
// 2) Webhook FPT -> Coze -> Response JSON
// =====================================
app.MapPost("/webhook/fpt", async (
    HttpRequest request,
    IHttpClientFactory httpClientFactory,
    IConfiguration config,
    IMemoryCache cache,
    ILogger<Program> log) =>
{
    var trace = request.HttpContext.TraceIdentifier;

    // Verify secret
    var expectedSecret = config["Fpt:WebhookSecret"];
    if (!VerifySecret(request, expectedSecret, "X-Webhook-Secret", log))
        return Results.Unauthorized();

    // Read body
    var raw = await new StreamReader(request.Body, Encoding.UTF8).ReadToEndAsync();
    if (string.IsNullOrWhiteSpace(raw))
    {
        return Results.Json(new
        {
            messages = new[] { new { type = "text", content = new { text = "Body rỗng." } } }
        });
    }

    using var doc = JsonDocument.Parse(raw);
    var root = doc.RootElement;

    string GetString(params string[] keys)
    {
        foreach (var k in keys)
        {
            if (root.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String)
            {
                var s = v.GetString();
                if (!string.IsNullOrWhiteSpace(s)) return s!;
            }
        }
        return "";
    }

    var senderId = GetString("sender_id", "senderId", "user_id", "userId");
    if (string.IsNullOrWhiteSpace(senderId)) senderId = "anonymous";

    var text = GetString("sender_input", "text", "message", "query");
    var conversationId = GetString("coze_conversation_id", "conversation_id");

    log.LogInformation("[FPT] trace={Trace} senderIdHash={SenderHash} textLen={Len} textPreview={Preview} cidExists={CidExists}",
        trace, Sha256Short(senderId), text?.Length ?? 0, Preview(text), !string.IsNullOrWhiteSpace(conversationId));

    if (string.IsNullOrWhiteSpace(text))
    {
        return Results.Json(new
        {
            messages = new[] { new { type = "text", content = new { text = "Bạn vui lòng nhập nội dung câu hỏi." } } }
        });
    }

    // Nếu request không gửi conversation_id thì thử cache theo senderId
    if (string.IsNullOrWhiteSpace(conversationId))
    {
        var key = $"fpt:cid:{senderId}";
        if (cache.TryGetValue(key, out string? cachedCid))
            conversationId = cachedCid ?? "";
    }

    var ct = request.HttpContext.RequestAborted;

    var (ok, answer, newCid, err) = await AskCozeAsync(
        httpClientFactory,
        config,
        log,
        userId: senderId,
        text: text,
        conversationId: conversationId,
        ct: ct);

    if (!ok)
    {
        log.LogWarning("[FPT] trace={Trace} coze failed: {Err}", trace, Preview(err, 300));
        answer = "Hệ thống đang bận hoặc cấu hình Coze chưa đúng. Vui lòng thử lại sau.";
    }

    // update cache (backup)
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
})
.WithName("FptWebhook");

app.Run();

