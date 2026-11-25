// Created & Architected by Shishir Vats | AEGIS-ZK Nitro Enclave Policy Server (Fail-Closed Production)
import http from 'http';
import fs from 'fs';
import {
  createPublicClient,
  http as viemHttp,
  encodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  parseAbi,
  parseUnits,
  keccak256,
  isAddress,
} from 'viem';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { baseSepolia } from 'viem/chains';

const enclaveAccount = privateKeyToAccount(generatePrivateKey());
const BASE_SEPOLIA_RPC = process.env.BASE_SEPOLIA_RPC || 'https://base.org';
const USDC_BASE_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e' as const;
const ORACLE_GUARD_ADDR = '0x165e8431B979F8A7d6D993A5727B7D6c6244f6F1' as const;
const MAX_APPROVED_USDC = parseUnits('1000', 6);
const NSM_DEVICE_PATH = '/dev/nsm';
const NITRO_ATTESTATION_FILE =
  process.env.NITRO_ATTESTATION_FILE || '/tmp/nitro_attestation.cbor';

const ERC20_ABI = parseAbi([
  'function transfer(address to, uint256 amount) external returns (bool)',
  'function approve(address spender, uint256 amount) external returns (bool)',
]);

const ORACLE_ABI = [
  {
    name: 'getValidatedOraclePrice18',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'token', type: 'address' }],
    outputs: [{ name: 'price18', type: 'uint256' }],
  },
] as const;

console.log(`[AEGIS NITRO ENCLAVE BOOTED] Volatile RAM Signer: ${enclaveAccount.address}`);

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    const hasHardwareNsm = fs.existsSync(NSM_DEVICE_PATH);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(
      JSON.stringify({
        status: 'ok',
        hardwareNitroNsm: hasHardwareNsm,
        enclaveSigner: enclaveAccount.address,
      })
    );
  }

  if (req.method === 'GET' && req.url === '/attestation') {
    if (!fs.existsSync(NSM_DEVICE_PATH) || !fs.existsSync(NITRO_ATTESTATION_FILE)) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(
        JSON.stringify({
          error:
            'Hardware AWS Nitro Security Module (/dev/nsm) attestation not present. Must execute inside an AWS Nitro Enclave.',
        })
      );
    }
    const coseBytes = fs.readFileSync(NITRO_ATTESTATION_FILE);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(
      JSON.stringify({
        enclaveSigner: enclaveAccount.address,
        coseAttestationHex: `0x${coseBytes.toString('hex')}`,
      })
    );
  }

  if (req.method === 'POST' && req.url === '/evaluate') {
    let raw = '';
    req.on('data', (chunk) => (raw += chunk));
    req.on('end', async () => {
      try {
        if (process.env.REQUIRE_HARDWARE_NSM === 'true' && !fs.existsSync(NSM_DEVICE_PATH)) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          return res.end(
            JSON.stringify({
              error: 'REQUIRE_HARDWARE_NSM=true but /dev/nsm is not present.',
            })
          );
        }

        const { prompt, smartAccount } = JSON.parse(raw);
        if (!prompt || typeof prompt !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Prompt string is required' }));
        }

        const client = createPublicClient({
          chain: baseSepolia,
          transport: viemHttp(BASE_SEPOLIA_RPC),
        });
        const currentBlock = await client.getBlockNumber();

        // Fail-closed Chainlink Oracle Guard verification (no silent catch fallback)
        const price18 = await client.readContract({
          address: ORACLE_GUARD_ADDR,
          abi: ORACLE_ABI,
          functionName: 'getValidatedOraclePrice18',
          args: [USDC_BASE_SEPOLIA],
          authorizationList: undefined,
        });
        const oracleTag = `Chainlink USDC: $${(Number(price18) / 1e18).toFixed(4)}`;

        const lower = prompt.toLowerCase();
        const isInjection = /ignore|override|system prompt|drain/.test(lower);
        const action = lower.includes('approve') ? 'approve' : 'transfer';
        const amountMatch = prompt.replace(/,/g, '').match(/(\d+(\.\d+)?)\s*usdc/i);
        const firstAmount = amountMatch?.at(1);
        const amountUsdc = firstAmount ? parseFloat(firstAmount) : 0;
        const addrMatch = prompt.match(/0x[a-fA-F0-9]{40}/g);
        const firstAddr = addrMatch?.at(0);
        const recipient = (
          firstAddr && isAddress(firstAddr)
            ? firstAddr
            : '0x000000000000000000000000000000000000dEaD'
        ) as `0x${string}`;

        const requestedUsdcRaw = parseUnits(amountUsdc.toString(), 6);
        const policyViolated =
          isInjection || action === 'approve' || requestedUsdcRaw > MAX_APPROVED_USDC;

        const validUntilBlock = policyViolated ? 0n : currentBlock + 25n;
        const signedMaxOutflowTokens = policyViolated ? [0n] : [requestedUsdcRaw];
        const spendersToVerifyZero = action === 'approve' ? [recipient] : [];

        const target =
          requestedUsdcRaw > 0n
            ? USDC_BASE_SEPOLIA
            : ('0x0000000000000000000000000000000000000000' as const);
        const targetCallData =
          requestedUsdcRaw > 0n
            ? encodeFunctionData({
                abi: ERC20_ABI,
                functionName: action,
                args: [recipient, requestedUsdcRaw],
              })
            : ('0x' as const);

        const mode =
          '0x0000000000000000000000000000000000000000000000000000000000000000' as const;

        const packedExecutionCalldata = encodePacked(
          ['address', 'uint256', 'bytes'],
          [target, 0n, targetCallData]
        );

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
            packedExecutionCalldata,
            validUntilBlock,
            0n,
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
        const enclaveSignature = await enclaveAccount.signMessage({ message: { raw: digest } });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            enclaveApproved: !policyViolated,
            reason: policyViolated
              ? `Blocked by AWS Nitro Enclave Policy Firewall (${oracleTag})`
              : `Nitro Enclave Signed (${oracleTag} | validUntilBlock: ${validUntilBlock})`,
            enclaveSigner: enclaveAccount.address,
            enclaveSignature,
            currentBlock: currentBlock.toString(),
            validUntilBlock: validUntilBlock.toString(),
            hookEnvelope,
            target,
            targetCallData,
          })
        );
      } catch (e: unknown) {
        const message = e instanceof Error ? e.message : 'Enclave evaluation failed';
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: message }));
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
