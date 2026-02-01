import { calculate, formatInputsForPrompt, UserInputs } from './calculate';
import { SYSTEM_PROMPT } from './prompt';
import { 
  SECURITY_HEADERS, 
  validateRequest, 
  sanitizeInputs,
  verifyTurnstile,
  checkHoneypot,
  detectSuspicious,
} from './security';

interface Env {
  AI: Ai;
  TURNSTILE_SECRET?: string;
  TURNSTILE_ENABLED: string;
}

// Simple in-memory rate limiting (resets on worker restart)
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT = 30; // Increased for better UX
const RATE_WINDOW = 60 * 1000;

function checkRateLimit(ip: string): { allowed: boolean; remaining: number; retryAfter: number } {
  const now = Date.now();
  const record = rateLimitMap.get(ip);
  
  if (!record || now > record.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_WINDOW });
    return { allowed: true, remaining: RATE_LIMIT - 1, retryAfter: 0 };
  }
  
  if (record.count >= RATE_LIMIT) {
    return { allowed: false, remaining: 0, retryAfter: Math.ceil((record.resetAt - now) / 1000) };
  }
  
  record.count++;
  return { allowed: true, remaining: RATE_LIMIT - record.count, retryAfter: 0 };
}

// Simple logging (to console, could be extended to external service)
function logEvent(event: string, data: Record<string, unknown> = {}) {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), event, ...data }));
}

function addSecurityHeaders(response: Response): Response {
  const newHeaders = new Headers(response.headers);
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    newHeaders.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}

function jsonResponse(data: object, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      ...extraHeaders,
    },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    
    // Get client IP
    const clientIP = request.headers.get('cf-connecting-ip') || 
                     request.headers.get('x-forwarded-for')?.split(',')[0] || 
                     'unknown';
    
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return addSecurityHeaders(new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
        },
      }));
    }
    
    // API endpoint
    if (url.pathname === '/api/generate' && request.method === 'POST') {
      
      // Rate limiting
      const rateLimit = checkRateLimit(clientIP);
      if (!rateLimit.allowed) {
        logEvent('rate_limited', { ip: clientIP });
        return addSecurityHeaders(jsonResponse(
          { error: 'Too many requests. Please wait a minute.' },
          429,
          { 
            'Retry-After': String(rateLimit.retryAfter), 
            'X-RateLimit-Remaining': '0' 
          }
        ));
      }
      
      // Validate request
      const validation = validateRequest(request);
      if (!validation.valid) {
        return addSecurityHeaders(jsonResponse({ error: validation.error }, 400));
      }
      
      try {
        // Parse body
        let rawInputs: Record<string, unknown>;
        try {
          rawInputs = await request.json();
        } catch {
          return addSecurityHeaders(jsonResponse({ error: 'Invalid JSON' }, 400));
        }
        
        // Honeypot check
        if (!checkHoneypot(rawInputs._hp)) {
          logEvent('honeypot_triggered', { ip: clientIP });
          // Return fake success to confuse bots
          return addSecurityHeaders(jsonResponse({ success: true, program: 'Generated.' }));
        }
        
        // Detect suspicious patterns
        const suspicious = detectSuspicious(request, rawInputs);
        if (suspicious) {
          logEvent(suspicious, { ip: clientIP, sample: JSON.stringify(rawInputs).slice(0, 100) });
          return addSecurityHeaders(jsonResponse({ error: 'Invalid request' }, 400));
        }
        
        // Turnstile verification
        if (env.TURNSTILE_ENABLED === 'true' && env.TURNSTILE_SECRET) {
          const turnstileToken = rawInputs.turnstileToken as string;
          const verified = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET, clientIP);
          
          if (!verified) {
            logEvent('turnstile_failed', { ip: clientIP });
            return addSecurityHeaders(jsonResponse(
              { error: 'Verification failed. Please refresh and try again.' }, 
              403
            ));
          }
        }
        
        // Sanitize inputs
        const inputs = sanitizeInputs(rawInputs) as unknown as UserInputs;
        
        // Validation
        if (inputs.targetWeight >= inputs.weight) {
          return addSecurityHeaders(jsonResponse(
            { error: 'Target weight must be less than current weight' }, 
            400
          ));
        }
        
        if (inputs.cardioModalities.length === 0) {
          return addSecurityHeaders(jsonResponse(
            { error: 'At least one cardio modality required' }, 
            400
          ));
        }
        
        // Calculate
        const calcs = calculate(inputs);
        const userContext = formatInputsForPrompt(inputs, calcs);
        
        // Generate program
        const response = await env.AI.run('@cf/meta/llama-3.1-70b-instruct', {
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: `Generate a complete 12-week program for this user:\n\n${userContext}` }
          ],
          max_tokens: 4000,
        });
        
        const program = (response as { response: string }).response;
        
        logEvent('program_generated', { ip: clientIP });
        
        return addSecurityHeaders(jsonResponse({
          success: true,
          calculations: calcs,
          program,
        }, 200, { 'X-RateLimit-Remaining': String(rateLimit.remaining) }));
        
      } catch (error) {
        console.error('Error:', error);
        logEvent('error', { ip: clientIP, message: error instanceof Error ? error.message : 'Unknown' });
        return addSecurityHeaders(jsonResponse(
          { error: 'An error occurred. Please try again.' }, 
          500
        ));
      }
    }
    
    return addSecurityHeaders(new Response('Not found', { status: 404 }));
  },
};
