// Groq via its OpenAI-compatible REST API. Same interface as gemini.js / claude.js.
const API = 'https://api.groq.com/openai/v1/chat/completions';
const MODEL = Deno.env.get('GROQ_MODEL') ?? 'openai/gpt-oss-20b';
const ATTEMPT_TIMEOUT_MS = 15000;

class RetryableError extends Error {}

async function attempt(messages, schema, maxTokens) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ATTEMPT_TIMEOUT_MS);

  const body = {
    model: MODEL,
    messages,
    max_tokens: maxTokens,
    temperature: 0.3,
    ...(schema ? { response_format: { type: 'json_object' } } : {}),
  };

  try {
    const res = await fetch(API, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'authorization': `Bearer ${Deno.env.get('GROQ_API_KEY')}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (res.status === 429 || res.status >= 500) {
      throw new RetryableError(`Groq ${res.status}`);
    }

    const data = await res.json();
    if (!res.ok) throw new Error(`Groq ${res.status}: ${data?.error?.message ?? ''}`);

    const text = data.choices?.[0]?.message?.content ?? '';
    if (!text) throw new RetryableError('Groq returned no text');
    return text;
  } catch (err) {
    if (err.name === 'AbortError') throw new RetryableError('Groq timed out');
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// One short JSON-returning call. Compatible with callGemini / callClaude interface.
export async function callGroq({ system, user, schema, maxTokens = 2000 }) {
  const messages = [
    { role: 'system', content: system },
    { role: 'user', content: user },
  ];

  let lastError;
  for (let i = 0; i < 2; i++) {
    try {
      return await attempt(messages, schema, maxTokens);
    } catch (err) {
      lastError = err;
      if (!(err instanceof RetryableError)) throw err;
      console.error(`${err.message}; retrying…`);
      await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
    }
  }
  throw lastError;
}
