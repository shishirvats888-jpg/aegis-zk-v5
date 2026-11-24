// Created & Architected by Shishir Vats | AEGIS-ZK v5.2 Enclave Policy API
import { NextRequest, NextResponse } from 'next/server';
import {
  createPublicClient,
  http,
  encodeAbiParameters,
  encodeFunctionData,
  parseAbi,
  parseUnits,
  keccak256,
  isAddress,
} from 'viem';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { baseSepolia } from 'viem/chains';

const USDC_BASE_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e' as const;
const MAX_APPROVED_USDC = parseUnits('1000', 6); // 1,000 USDC policy cap

const ERC20_ABI = parseAbi([
  'function transfer(address to, uint256 amount) external returns (bool)',
  'function approve(address spender, uint256 amount) external returns (bool)',
]);

async function parseAgentIntent(prompt: string) {
  if (process.env.LLM_API_KEY) {
    const res = await fetch('https://openai.com', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.LLM_API_KEY}`,
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        temperature: 0,
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content:
              'Extract DeFi intent as JSON: {"action":"transfer"|"approve"|"swap","amountUsdc":number,"recipient":"0x...","isInjection":boolean}. Default recipient to 0x000000000000000000000000000000000000dEaD if none.',
          },
          { role: 'user', content: prompt },
        ],
      }),
    });
    const data = await res.json();
    const parsed = JSON.parse(data.choices[0].message.content);
    return {
      action: parsed.action || 'transfer',
      amountUsdc: Number(parsed.amountUsdc || 0),
      recipient: isAddress(parsed.recipient)
        ? (parsed.recipient as `0x${string}`)
        : ('0x000000000000000000000000000000000000dEaD' as const),
      isInjection: Boolean(parsed.isInjection),
    };
  }

  const lower = prompt.toLowerCase();
  const isInjection =
    lower.includes('ignore') ||
    lower.includes('override') ||
    lower.includes('system prompt') ||
    lower.includes('drain');
  const action = lower.includes('approve') ? 'approve' : 'transfer';
  const amountMatch = prompt.replace(/,/g, '').match(/(\d+(\.\d+)?)\s*usdc/i);
  const amountUsdc = amountMatch ? parseFloat(amountMatch[1]) : 0;
  const addrMatch = prompt.match(/0x[a-fA-F0-9]{40}/);
  const recipient = addrMatch
    ? (addrMatch[0] as `0x${string}`)
    : ('0x000000000000000000000000000000000000dEaD' as const);

  return { action, amountUsdc, recipient, isInjection };
}

export async function POST(req: NextRequest) {
  try {
    const { prompt, smartAccount } = await req.json();
    const enclaveAccount = privateKeyToAccount(generatePrivateKey());
    const client = createPublicClient({ chain: baseSepolia, transport: http() });
    const currentBlock = await client.getBlockNumber();

    const intent = await parseAgentIntent(prompt);
    const requestedUsdcRaw = parseUnits(intent.amountUsdc.toString(), 6);

    const policyViolated =
      intent.isInjection ||
      intent.action === 'approve' ||
      requestedUsdcRaw > MAX_APPROVED_USDC;

    const validUntilBlock = policyViolated ? 0n : currentBlock + 15n;
    const signedMaxOutflowEth = 0n;
    const signedMaxOutflowTokens = policyViolated ? [0n] : [requestedUsdcRaw];
    const spendersToVerifyZero =
      intent.action === 'approve' ? [intent.recipient] : [];

    const target =
      requestedUsdcRaw > 0n
        ? USDC_BASE_SEPOLIA
        : '0x0000000000000000000000000000000000000000';
    const targetCallData =
      requestedUsdcRaw > 0n
        ? encodeFunctionData({
            abi: ERC20_ABI,
            functionName: intent.action === 'approve' ? 'approve' : 'transfer',
            args: [intent.recipient, requestedUsdcRaw],
          })
        : '0x';

    const mode =
      '0x0000000000000000000000000000000000000000000000000000000000000000' as const;

    const hookEnvelope = encodeAbiParameters(
      [
        { type: 'bytes32' },
        { type: 'bytes' },
        { type: 'uint256' },
        { type: 'uint256' },
        { type: 'uint256[]' },
        { type: 'address[]' },
      ],
      [
        mode,
        targetCallData,
        validUntilBlock,
        signedMaxOutflowEth,
        signedMaxOutflowTokens,
        spendersToVerifyZero,
      ]
    );

    const maxOutflowHash = keccak256(
      encodeAbiParameters([{ type: 'uint256[]' }], [signedMaxOutflowTokens])
    );
    const digest = keccak256(
      encodeAbiParameters(
        [
          { type: 'bytes32' },
          { type: 'uint256' },
          { type: 'address' },
          { type: 'uint256' },
          { type: 'bytes32' },
        ],
        [
          keccak256(hookEnvelope),
          BigInt(baseSepolia.id),
          (smartAccount || enclaveAccount.address) as `0x${string}`,
          validUntilBlock,
          maxOutflowHash,
        ]
      )
    );
    const enclaveSignature = await enclaveAccount.signMessage({
      message: { raw: digest },
    });

    return NextResponse.json({
      enclaveApproved: !policyViolated,
      reason: policyViolated
        ? `Rejected policy envelope (${
            intent.isInjection
              ? 'Adversarial Prompt Injection'
              : intent.action === 'approve'
              ? 'Unbounded ERC-20 Approval Blocked'
              : `Outflow ${intent.amountUsdc} USDC > 1,000 USDC Cap`
          })`
        : `Enclave signed envelope (validUntilBlock: ${validUntilBlock.toString()})`,
      enclaveSigner: enclaveAccount.address,
      enclaveSignature,
      currentBlock: currentBlock.toString(),
      validUntilBlock: validUntilBlock.toString(),
      hookEnvelope,
      target,
      targetCallData,
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err.message || 'Enclave API error' },
      { status: 500 }
    );
  }
}
