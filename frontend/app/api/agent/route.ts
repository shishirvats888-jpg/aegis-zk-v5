import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const prompt = String(body?.prompt ?? '').trim();
    const smartAccount = String(body?.smartAccount ?? '').trim();
    const userOpHash = typeof body?.userOpHash === 'string' ? body.userOpHash.trim() : undefined;

    if (!prompt) {
      return NextResponse.json({ error: 'Prompt is required' }, { status: 400 });
    }

    const enclaveUrl = process.env.ENCLAVE_URL;
    if (!enclaveUrl) {
      return NextResponse.json(
        {
          error:
            'ENCLAVE_URL is not configured. Connect a live AWS Nitro Enclave endpoint (agent-enclave-runner) — zero local fallback permitted.',
        },
        { status: 503 }
      );
    }

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (process.env.REDTEAM_ACCESS_CODE) {
      headers['x-aegis-access-code'] = process.env.REDTEAM_ACCESS_CODE;
    }

    const teeRes = await fetch(`${enclaveUrl.replace(/\/$/, '')}/evaluate`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        prompt,
        smartAccount,
        userOpHash,
        accessCode: process.env.REDTEAM_ACCESS_CODE || undefined,
      }),
      signal: AbortSignal.timeout(25_000),
    });

    const teeJson = await teeRes.json();
    if (!teeRes.ok) {
      return NextResponse.json(
        { error: teeJson.error || 'AWS Nitro Enclave rejected request' },
        { status: teeRes.status }
      );
    }

    return NextResponse.json(teeJson);
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : 'Failed to reach AWS Nitro Enclave';
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
