'use client';

import React, { useEffect, useMemo, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';

import {
  documentAPI,
  DocumentVerificationPayload,
  ProofVerificationResponse,
  SchnorrProof,
} from '../../services/api';
import { normalizeText } from '../../utils/normalization';
import { generateSchnorrProof, hashNormalizedText, scalarFromHash } from '../../utils/schnorr';

const PROOF_CONTEXT = 'web-client:v1';

export default function VerifyPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const initialDocId = searchParams.get('docId') || '';

  const [docIdInput, setDocIdInput] = useState(initialDocId);
  const [verificationData, setVerificationData] = useState<DocumentVerificationPayload | null>(null);
  const [loading, setLoading] = useState<boolean>(Boolean(initialDocId));
  const [error, setError] = useState<string | null>(null);
  const [fetching, setFetching] = useState<boolean>(false);

  const [rawText, setRawText] = useState('');
  const [normalizedPreview, setNormalizedPreview] = useState('');
  const [hashPreview, setHashPreview] = useState('');
  const [proofPreview, setProofPreview] = useState<SchnorrProof | null>(null);
  const [proofResult, setProofResult] = useState<ProofVerificationResponse | null>(null);
  const [proofError, setProofError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState<boolean>(false);

  const docId = useMemo(() => initialDocId.toUpperCase(), [initialDocId]);

  useEffect(() => {
    const fetchVerificationData = async (id: string) => {
      if (!id) {
        setLoading(false);
        setVerificationData(null);
        return;
      }

      try {
        setLoading(true);
        setError(null);
        const payload = await documentAPI.getVerification(id);
        setVerificationData(payload);
      } catch (err: any) {
        console.error('Failed to fetch verification payload', err);
        setVerificationData(null);
        setError(err?.message || 'Unable to fetch verification payload.');
      } finally {
        setLoading(false);
      }
    };

    fetchVerificationData(docId);
  }, [docId]);

  const handleLookup = async (event: React.FormEvent) => {
    event.preventDefault();
    const sanitized = docIdInput.trim().toUpperCase();
    if (!sanitized) {
      setError('Please enter a document ID from the physical letter or QR code.');
      return;
    }

    setFetching(true);
    setError(null);
    setProofResult(null);
    setProofPreview(null);
    setNormalizedPreview('');
    setHashPreview('');

    router.push(`/verify?docId=${encodeURIComponent(sanitized)}`);
    setFetching(false);
  };

  const handleGenerateAndVerify = async () => {
    if (!verificationData) {
      setProofError('Load a document before generating a proof.');
      return;
    }

    if (!rawText.trim()) {
      setProofError('Paste OCR output or typed text from the physical letter.');
      return;
    }

    try {
      setVerifying(true);
      setProofError(null);
      setProofResult(null);

      const normalized = normalizeText(rawText);
      setNormalizedPreview(normalized);

      const hashHex = hashNormalizedText(normalized);
      if (!hashHex) {
        throw new Error('Normalization produced empty text. Confirm the letter content.');
      }
      setHashPreview(hashHex);

      const scalar = scalarFromHash(hashHex);
      if (!scalar) {
        throw new Error('Unable to derive scalar from text hash.');
      }

      const proof = generateSchnorrProof(scalar, verificationData.zk_commitment, verificationData.id, PROOF_CONTEXT);
      setProofPreview(proof);

      const response = await documentAPI.verifyProof(verificationData.id, {
        proof,
        context: PROOF_CONTEXT,
      });

      setProofResult(response);
    } catch (err: any) {
      console.error('Proof generation failed', err);
      setProofError(err?.message || 'Failed to generate or verify proof.');
    } finally {
      setVerifying(false);
    }
  };

  const renderLookupForm = () => (
    <form onSubmit={handleLookup} className="bg-white shadow rounded-lg p-6 mb-6">
      <h2 className="text-lg font-semibold text-gray-900 mb-2">Start Verification</h2>
      <p className="text-sm text-gray-500 mb-4">
        Scan the QR code or enter the document ID printed on the letter. You will then be able to
        generate a zero-knowledge proof without uploading the letter contents.
      </p>
      <div className="flex flex-col sm:flex-row gap-3">
        <input
          type="text"
          value={docIdInput}
          onChange={(event) => setDocIdInput(event.target.value)}
          className="flex-1 rounded-md border border-gray-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          placeholder="INV-1234-5678"
          aria-label="Document ID"
        />
        <button
          type="submit"
          className="inline-flex justify-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50"
          disabled={fetching}
        >
          {fetching ? 'Loading…' : 'Lookup'}
        </button>
      </div>
    </form>
  );

  const renderProofPanel = () => {
    if (!verificationData) return null;

    return (
      <div className="bg-white shadow rounded-lg p-6 space-y-6">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 mb-2">Proof of Authenticity</h2>
          <p className="text-sm text-gray-500">
            Paste OCR output or the typed text from the physical letter. The proof is generated in
            your browser; the backend only receives the proof packet.
          </p>
        </div>

        <div>
          <label htmlFor="rawText" className="block text-sm font-medium text-gray-700 mb-1">
            OCR Text
          </label>
          <textarea
            id="rawText"
            rows={6}
            value={rawText}
            onChange={(event) => setRawText(event.target.value)}
            className="w-full rounded-md border border-gray-300 px-3 py-2 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            placeholder="Paste the scanned text from the physical letter here…"
          />
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <button
            type="button"
            onClick={handleGenerateAndVerify}
            className="inline-flex justify-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50"
            disabled={verifying}
          >
            {verifying ? 'Generating proof…' : 'Generate & Submit Proof'}
          </button>
          <Link
            href="/dashboard"
            className="inline-flex justify-center rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 shadow hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
          >
            Back to Dashboard
          </Link>
        </div>

        {proofError && (
          <div className="rounded-md bg-red-50 p-4 border border-red-200 text-red-700 text-sm">
            {proofError}
          </div>
        )}

        {proofResult && (
          <div className="rounded-md bg-green-50 p-4 border border-green-200 text-green-700 text-sm">
            Proof verified at {new Date(proofResult.verified_at).toLocaleString()} for document{' '}
            {proofResult.document_id}.
          </div>
        )}

        {(normalizedPreview || hashPreview || proofPreview) && (
          <div className="rounded-md bg-gray-50 border border-gray-200 p-4 space-y-2 text-sm text-gray-600">
            <div>
              <span className="font-semibold text-gray-700">Normalized Text:</span>
              <p className="mt-1 whitespace-pre-wrap break-words">{normalizedPreview || '—'}</p>
            </div>
            <div>
              <span className="font-semibold text-gray-700">Text Hash (SHA-256):</span>
              <p className="mt-1 break-all font-mono text-xs">{hashPreview || '—'}</p>
            </div>
            {proofPreview && (
              <div className="space-y-1">
                <span className="font-semibold text-gray-700">Schnorr Proof:</span>
                <p className="font-mono text-xs break-all">rx: {proofPreview.rx}</p>
                <p className="font-mono text-xs break-all">ry: {proofPreview.ry}</p>
                <p className="font-mono text-xs break-all">s: {proofPreview.s}</p>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  const renderVerificationDetails = () => {
    if (!verificationData) {
      return (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6 text-sm text-yellow-800">
          Load a document to view verification metadata, QR payload, and checksum hints.
        </div>
      );
    }

    const { id, file_hash, issued_at, normalization_strategy, zk_commitment, checksum, qr_png_base64 } =
      verificationData;

    return (
      <div className="bg-white shadow rounded-lg p-6 space-y-6">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 mb-2">Verification Metadata</h2>
          <p className="text-sm text-gray-500">
            These values come from the signed payload encoded in the QR code and blockchain record.
            Compare the checksum printed on the letter with the one below.
          </p>
        </div>

        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <dt className="text-sm font-medium text-gray-500">Document ID</dt>
            <dd className="mt-1 text-sm text-gray-900">{id}</dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">Issued At</dt>
            <dd className="mt-1 text-sm text-gray-900">{new Date(issued_at).toLocaleString()}</dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-sm font-medium text-gray-500">File Hash</dt>
            <dd className="mt-1 text-sm text-gray-900 break-all font-mono">{file_hash}</dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-sm font-medium text-gray-500">ZK Commitment</dt>
            <dd className="mt-1 text-sm text-gray-900 break-all font-mono">{zk_commitment}</dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">Normalization Strategy</dt>
            <dd className="mt-1 text-sm text-gray-900">{normalization_strategy}</dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">Checksum</dt>
            <dd className="mt-1 text-lg font-semibold text-indigo-600">{checksum}</dd>
          </div>
        </dl>

        <div>
          <dt className="text-sm font-medium text-gray-500 mb-2">QR Code Payload</dt>
          <div className="inline-block rounded-md border border-gray-200 bg-white p-3">
            <img
              src={`data:image/png;base64,${qr_png_base64}`}
              alt="Verification QR code"
              className="h-48 w-48"
            />
          </div>
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-4">
        <div className="w-16 h-16 border-t-4 border-indigo-500 border-solid rounded-full animate-spin mb-4" />
        <h2 className="text-xl font-medium text-gray-700">Loading verification data…</h2>
        <p className="text-gray-500 mt-2">Hold tight while we fetch the signed payload.</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Verify Physical Letter</h1>
            <p className="mt-2 text-sm text-gray-600">
              Generate a zero-knowledge proof that the physical letter you hold matches the document
              committed on-chain.
            </p>
          </div>
        </div>

        {error && (
          <div className="rounded-md bg-red-50 border border-red-200 p-4 text-sm text-red-700">
            {error}
          </div>
        )}

        {renderLookupForm()}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {renderVerificationDetails()}
          {renderProofPanel()}
        </div>

        <div className="bg-white shadow rounded-lg p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-3">Manual Checks</h2>
          <ul className="list-disc list-inside text-sm text-gray-600 space-y-2">
            <li>
              Ensure the checksum printed on the letter matches <span className="font-mono">{verificationData?.checksum || '—'}</span>. Any mismatch indicates tampering.
            </li>
            <li>
              The QR code encodes the commitment and signature; if scanning redirects to a different ID, reject the letter.
            </li>
            <li>
              Keep the normalization strategy consistent when generating proofs. Changing punctuation or casing alters the hash.
            </li>
            <li>
              Proofs include browser context <span className="font-mono">{PROOF_CONTEXT}</span> to prevent replay in other channels.
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
