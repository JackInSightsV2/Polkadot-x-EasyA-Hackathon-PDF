import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

const ORDER = secp.CURVE.n;
const textEncoder = new TextEncoder();

const mod = (value: bigint, modulo: bigint) => {
  const result = value % modulo;
  return result >= 0n ? result : result + modulo;
};

const concatUint8Arrays = (arrays: Uint8Array[]): Uint8Array => {
  const totalLength = arrays.reduce((total, arr) => total + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  arrays.forEach((arr) => {
    result.set(arr, offset);
    offset += arr.length;
  });
  return result;
};

export interface SchnorrProof {
  rx: string;
  ry: string;
  s: string;
}

export function hashNormalizedText(normalized: string): string {
  if (!normalized) return '';
  const bytes = textEncoder.encode(normalized);
  return bytesToHex(sha256(bytes));
}

export function scalarFromHash(hashHex: string): bigint {
  if (!hashHex) return 0n;
  const scalar = mod(BigInt(`0x${hashHex}`), ORDER);
  return scalar === 0n ? 1n : scalar;
}

const numberToHex = (value: bigint) => value.toString(16).padStart(64, '0');

function deriveChallenge(
  R: secp.Point,
  commitmentHex: string,
  documentId: string,
  context: string
): bigint {
  const rxBytes = secp.utils.numberToBytesBE(R.x, 32);
  const ryBytes = secp.utils.numberToBytesBE(R.y, 32);
  const commitmentBytes = secp.utils.hexToBytes(commitmentHex);
  const docIdBytes = textEncoder.encode(documentId);
  const contextBytes = textEncoder.encode(context);

  const challengeMaterial = concatUint8Arrays([
    rxBytes,
    ryBytes,
    commitmentBytes,
    docIdBytes,
    contextBytes,
  ]);

  const challengeHash = sha256(challengeMaterial);
  return mod(secp.utils.bytesToNumberBE(challengeHash), ORDER);
}

export function generateSchnorrProof(
  scalar: bigint,
  commitmentHex: string,
  documentId: string,
  context: string
): SchnorrProof {
  let r = mod(secp.utils.bytesToNumberBE(secp.utils.randomPrivateKey()), ORDER);
  if (r === 0n) {
    r = 1n;
  }

  const R = secp.Point.BASE.multiply(r);
  const challenge = deriveChallenge(R, commitmentHex, documentId, context);
  const s = mod(r + challenge * scalar, ORDER);

  return {
    rx: numberToHex(R.x),
    ry: numberToHex(R.y),
    s: numberToHex(s),
  };
}
