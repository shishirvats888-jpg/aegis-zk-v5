// Created & Architected by Shishir Vats | AEGIS-ZK Nitro Enclave Policy Server
import http from 'http';
import {
  createPublicClient,
  http as viemHttp,
  encodeAbiParameters,
  encodeFunctionData,
  parseAbi,
  parseUnits,
  keccak256,
  isAddress,
} from 'viem';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { baseSepolia } from 'viem/chains';

const enclaveAccount = privateKeyToAccount(generatePrivateKey());
const USDC_BASE_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e' as const;
const MAX_APPROVED_USDC = parseUnits('1000', 6);

const ERC20_ABI = parseAbi([
  'function transfer(address to, uint256 amount) external returns (bool)',
  'function approve(address spender, uint256 amount) external returns (bool)',
]);

console.log(`[AEGIS NITRO ENCLAVE BOOTED] Volatile RAM Signer: ${enclaveAccount.address}`);

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'ok', enclaveSigner: enclaveAccount.address }));
  }

  if (req.method === 'POST' && req.url === '/evaluate') {
    let raw = '';
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', async () => {
      try {
        const { prompt, smartAccount } = JSON.parse(raw);
        const client = createPublicClient({ chain: baseSepolia, transport: viemHttp() });
        const currentBlock = await client.getBlockNumber();

        const lower = String(prompt || '').toLowerCase();
        const isInjection = /ignore|override|system prompt|drain/.test(lower);
        const action = lower.includes('approve') ? 'approve' : 'transfer';
        const amountMatch = String(prompt || '').replace(/,/g, '').match(/(\d+(\.\d+)?)\s*usdc/i);
        const amountUsdc = amountMatch ? parseFloat(amountMatch[1]) : 0;
        const addrMatch = String(prompt || '').match(/0x[a-fA-F0-9]{40}/);
        const recipient = (addrMatch && isAddress(addrMatch[0])
          ? addrMatch[0]
          : '0x000000000000000000000000000000000000dEaD') as `0x${string}`;

        const requestedUsdcRaw = parseUnits(amountUsdc.toString(), 6);
        const policyViolated =
          isInjection || action === 'approve' || requestedUsdcRaw > MAX_APPROVED_USDC;

        const validUntilBlock = policyViolated ? 0n : currentBlock + 15n;
        const signedMaxOutflowTokens = policyViolated ? [0n] : [requestedUsdcRaw];
        const spendersToVerifyZero = action === 'approve' ? [recipient] : [];

        const target =
          requestedUsdcRaw > 0n
            ? USDC_BASE_SEPOLIA
            : '0x0000000000000000000000000000000000000000';
        const targetCallData =
          requestedUsdcRaw > 0n
            ? encodeFunctionData({
                abi: ERC20_ABI,
                functionName: action,
                args: [recipient, requestedUsdcRaw],
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
          [mode, targetCallData, validUntilBlock, 0n, signedMaxOutflowTokens, spendersToVerifyZero]
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
        const enclaveSignature = await enclaveAccount.signMessage({ message: { raw: digest } });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            enclaveApproved: !policyViolated,
            reason: policyViolated
              ? 'Blocked by AWS Nitro Enclave Policy Firewall'
              : `Nitro Enclave Signed (validUntilBlock: ${validUntilBlock})`,
            enclaveSigner: enclaveAccount.address,
            enclaveSignature,
            currentBlock: currentBlock.toString(),
            validUntilBlock: validUntilBlock.toString(),
            hookEnvelope,
            target,
            targetCallData,
          })
        );
      } catch (e: any) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end();
});

server.listen(5000, '0.0.0.0', () => {
  console.log('AEGIS-ZK Enclave Policy Server listening on port 5000');
});
