# Physical Letter Zero-Knowledge Verification

This guide documents the end-to-end flow for issuing verifiable physical letters and proving their authenticity without revealing document contents. The implementation combines deterministic text hashing, Schnorr commitments, QR code attestations, and an interactive ZK proof exchange between the holder and verifier.

## Architecture Overview

- **Deterministic text pipeline** – PDFs are parsed with `pypdf`, normalized (Unicode NFKC, lowercase, whitespace collapse), and hashed with SHA-256.
- **Commitment derivation** – The text hash is mapped into the secp256k1 scalar field and used to derive a public commitment (`zk_commitment`). This acts as the on-chain/public anchor for the document’s wording.
- **Attestation package** – The backend signs `{doc_id, file_hash, issued_at, normalization_strategy, zk_commitment, checksum}` with an HMAC secret and renders a QR code that embeds the payload. A short checksum (12 hex characters) is surfaced for quick human comparison.
- **Client proof generation** – The verification page normalizes OCR text locally, recreates the scalar, and produces a Schnorr proof proving knowledge of the committed scalar while keeping the text private.
- **Server verification** – The backend checks the Schnorr relation against the stored commitment and returns a success response without receiving the plaintext content.

All logic is split into reusable services (`services/text_processing.py`, `services/zk_proof.py`, `services/qr_payload.py`, `services/signature.py`) to keep the implementation modular and future-proof for alternative proof systems.

## Backend Setup

1. **Install dependencies**

   ```bash
   cd backend
   pip install -r requirements.txt
   ```

   New packages: `pypdf`, `qrcode`, `Pillow`, `ecdsa`.

2. **Environment variable**

   Set a strong signing secret so QR payloads cannot be forged:

   ```bash
   export DOCUMENT_SIGNING_SECRET="base64-or-hex-secret-of-your-choice"
   ```

   In production, manage this secret via your deployment platform’s secret store.

3. **Run the API**

   ```bash
   uvicorn main:app --reload
   ```

4. **Behavioral changes**
   - `/upload` now extracts text, builds a Schnorr commitment, signs the verification payload, and stores QR data alongside metadata.
   - `/document/{id}/verification` returns the attestation packet (commitment, checksum, QR payload, etc.).
   - `/document/{id}/zk-verify` accepts Schnorr proofs and verifies them server-side.

Existing metadata is upgraded on-demand; fetching the verification payload recomputes missing signatures/QR codes and persists them to `uploads/metadata/documents.json`.

## Frontend Setup

1. **Install dependencies**

   ```bash
   cd frontend/stamping/web
   npm install
   ```

   New packages: `@noble/secp256k1`, `@noble/hashes`.

2. **Configure API base URL**

   Create/update `.env.local`:

   ```
   NEXT_PUBLIC_API_URL=http://localhost:8000
   ```

3. **Run the app**

   ```bash
   npm run dev
   ```

4. **Key UI changes**
   - `/verify` allows scanning/entering a document ID, loads the signed payload, and displays the QR image and checksum.
   - Clients paste OCR text, generate a Schnorr proof locally, and submit it for validation without leaking the underlying text.
   - Normalization utilities mirror the backend logic to guarantee identical hashes.

## Issuance Flow (Backoffice)

1. Upload PDF via existing `/upload` endpoint/UI.
2. Backend stores:
   - Raw file hash (`file_hash`)
   - Normalized text hash (`normalized_text_hash`)
   - Schnorr commitment (`zk_commitment`)
   - Signed verification payload (`signature`, `checksum`, `qr_payload`, `qr_png_base64`)
3. Embed the generated QR code and checksum into the printed letter.
4. Optionally persist the checksum in ledger/on-chain storage for revocation tracking.

## Verification Flow (End User)

1. Scan the QR code or manually enter the document ID on `/verify`.
2. Confirm the displayed checksum matches the printed value; mismatch implies tampering.
3. Paste OCR output of the physical letter (or use a deterministic capture pipeline).
4. Click **Generate & Submit Proof**:
   - Browser normalizes the text, hashes it, derives the scalar, and creates a Schnorr proof.
   - Backend validates the proof against the stored commitment and returns a signed confirmation.
   - No plaintext leaves the device.
5. (Optional) Archive the returned `{status, document_id, verified_at}` tuple for audit logs.

## Extensibility

- **Alternate proof systems**: Swap `generateSchnorrProof`/`verify_schnorr_proof` with Circom, Risc0, or Halo2 circuits. The modular service layout isolates the proof interface.
- **Additional metadata**: Extend `DocumentMetadata` and the QR payload to include issuer DIDs, revocation status, or chained commitments.
- **Revocation**: Append `status` updates and signature refreshes when documents are revoked/reissued.
- **Physical security**: Combine with tamper-evident paper, holograms, or watermarking. The checksum and signature already make tampering digitally detectable.

## Troubleshooting

- **Normalization mismatches**: Ensure OCR tooling preserves characters; stray whitespace differences change the hash. The normalization strategy is included in responses for reference.
- **Signature failures**: Rotate `DOCUMENT_SIGNING_SECRET` and reissue letters if the secret is compromised.
- **Legacy documents**: Fetching `/document/{id}/verification` automatically backfills missing QR data and signatures using current secrets.

## Next Steps

- Automate OCR capture in the verification UI (e.g. client-side Tesseract).
- Push commitments and signatures on-chain for immutable anchoring.
- Integrate revocation lists so verifiers know when to reject outdated letters.
- Replace HMAC signing with hardware-backed keys or DID-based signatures for decentralized trust models.
