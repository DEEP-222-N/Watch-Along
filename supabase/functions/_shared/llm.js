// Provider switch for the AI features.
// Priority: AI_PROVIDER env var → auto-detect from available keys (Groq → Gemini → Anthropic).
import { callClaude } from './claude.js';
import { callGemini } from './gemini.js';
import { callGroq } from './groq.js';

function detectProvider() {
  const explicit = Deno.env.get('AI_PROVIDER');
  if (explicit) return explicit;
  if (Deno.env.get('GROQ_API_KEY')) return 'groq';
  if (Deno.env.get('GEMINI_API_KEY')) return 'gemini';
  return 'anthropic';
}

const provider = detectProvider();

export function callModel(args) {
  if (provider === 'groq') return callGroq(args);
  if (provider === 'gemini') return callGemini(args);
  return callClaude(args);
}

export function parseJson(text) {
  const cleaned = String(text).trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
  return JSON.parse(cleaned);
}
