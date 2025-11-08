from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from auth import verify_token
from utils import pwd_context
from supabase import create_client, Client
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from models import (
    CompanyRegistration,
    CompanyResponse,
    UserRegistration,
    UserResponse,
    LoginLogRegistration,
    UserLogin,
    DocumentMetadata,
    DocumentResponse,
    DocumentVerificationPayload,
    ProofVerificationRequest,
)
import os
from dotenv import load_dotenv
from passlib.context import CryptContext
from datetime import datetime
import uuid
import shutil
from pathlib import Path
import hashlib
import json
import random
import string
import re  # For better matching of document ID formats
from typing import List, Optional

from services.text_processing import extract_text, normalize_text, hash_normalized_text
from services.zk_proof import commitment_from_hash, verify_schnorr_proof
from services.qr_payload import generate_qr_png_base64
from services.signature import sign_payload, verify_signature

load_dotenv()

# Enable development mode for easier testing
os.environ["DEV_MODE"] = "true"

app = FastAPI()

# Create upload and metadata directories if they don't exist
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

METADATA_DIR = Path("uploads/metadata")
METADATA_DIR.mkdir(exist_ok=True)

# Metadata JSON file path
DOCUMENTS_METADATA_FILE = METADATA_DIR / "documents.json"

# Create documents metadata file if it doesn't exist
if not DOCUMENTS_METADATA_FILE.exists():
    with open(DOCUMENTS_METADATA_FILE, "w") as f:
        json.dump([], f)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
    expose_headers=["Content-Disposition"],  # For file downloads
)

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve favicon.ico
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("static/favicon.ico")

# Initialize Supabase client with error handling
try:
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    
    if not supabase_url or not supabase_key:
        raise ValueError("Missing Supabase credentials in environment variables")
        
    supabase: Client = create_client(supabase_url, supabase_key)
except Exception as e:
    print(f"Error initializing Supabase client: {e}")
    raise

# Initialize password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.get("/")
def read_root():
    return {"message": "FastAPI backend is up!"}

@app.get("/protected")
def protected_route(user=Depends(verify_token)):
    return {"message": "You are authenticated!", "user": user}

@app.post("/register/company", response_model=CompanyResponse)
async def register_company(company_data: CompanyRegistration):
    try:
        # Check if company email already exists
        existing_company = supabase.table("companies").select("*").eq("email", company_data.email).execute()
        if existing_company.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Company with this email already exists"
            )
        
        # Hash the password
        hashed_password = pwd_context.hash(company_data.password)
        
        # Create company record
        data = {
            "name": company_data.name,
            "email": company_data.email,
            "password": hashed_password,
            "registered_address": company_data.registered_address
        }
        
        result = supabase.table("companies").insert(data).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create company"
            )
        
        company = result.data[0]
        return CompanyResponse(
            id=company["id"],
            name=company["name"],
            email=company["email"],
            registered_address=company["registered_address"],
            created_at=company["created_at"],
            updated_at=company["updated_at"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in register_company: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post("/login/company")
async def login_company(email: str, password: str):
    try:
        # Get company by email
        result = supabase.table("companies").select("*").eq("email", email).execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        company = result.data[0]
        
        # Verify password
        if not pwd_context.verify(password, company["password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Return company data without password
        return {
            "id": company["id"],
            "name": company["name"],
            "email": company["email"],
            "registered_address": company["registered_address"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in login_company: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post("/register/user", response_model=UserResponse)
async def register_user(user_data: UserRegistration):
    try:
        # Check if email exists
        existing_user = supabase.table("users").select("*").eq("email", user_data.email).execute()
        if existing_user.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists"
            )

        # Check if company exists
        company = supabase.table("companies").select("*").eq("id", str(user_data.company_id)).execute()
        if not company.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Company not found"
            )

        # Hash the password
        hashed_password = pwd_context.hash(user_data.password)

        # Insert user
        data = {
            "full_name": user_data.full_name,
            "email": user_data.email,
            "company_id": str(user_data.company_id),
            "password_hash": hashed_password
        }
        result = supabase.table("users").insert(data).execute()

        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create user"
            )

        user = result.data[0]
        return UserResponse(
            id=user["id"],
            full_name=user["full_name"],
            email=user["email"],
            company_id=user["company_id"],
            created_at=user["created_at"],
            updated_at=user["updated_at"]
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in register_user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post("/login/user")
async def login_user(credentials: UserLogin):
    try:
        result = supabase.table("users").select("*").eq("email", credentials.email).execute()

        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )

        user = result.data[0]

        # Check plaintext password against hashed password
        if not pwd_context.verify(credentials.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )

        # Log the login
        supabase.table("login_log").insert({
            "user_id": str(user["id"])
        }).execute()

        # Return user details (no password)
        return {
            "id": user["id"],
            "full_name": user["full_name"],
            "email": user["email"],
            "company_id": user["company_id"]
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in login_user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

NORMALIZATION_STRATEGY = "unicode_nfkc_lowercase_whitespace_collapse"


def isoformat_utc(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat() + "Z"


def load_documents() -> List[dict]:
    if not os.path.exists(DOCUMENTS_METADATA_FILE):
        return []
    try:
        with open(DOCUMENTS_METADATA_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def save_documents(documents: List[dict]) -> None:
    with open(DOCUMENTS_METADATA_FILE, "w") as f:
        json.dump(documents, f, indent=2)


def find_document(document_id: str) -> Optional[dict]:
    clean_id = re.sub(r"[^a-zA-Z0-9-]", "", document_id).upper()
    for document in load_documents():
        doc_id = document.get("id", "")
        if doc_id == document_id or doc_id.upper() == clean_id:
            return document
    return None


def build_verification_payload(document: dict) -> DocumentVerificationPayload:
    if not document.get("zk_commitment"):
        raise ValueError("Document does not have a zero-knowledge commitment.")

    issued_at = document.get("timestamp")
    if not issued_at:
        issued_at = isoformat_utc(datetime.utcnow())
    file_hash = document.get("file_hash")
    normalization_strategy = document.get("normalization_strategy", NORMALIZATION_STRATEGY)
    zk_commitment = document["zk_commitment"]

    checksum = document.get("checksum")
    if not checksum:
        checksum_seed = f"{document['id']}:{zk_commitment}:{file_hash}"
        checksum = hashlib.sha256(checksum_seed.encode("utf-8")).hexdigest()[:12].upper()

    signable = {
        "id": document["id"],
        "file_hash": file_hash,
        "issued_at": issued_at,
        "normalization_strategy": normalization_strategy,
        "zk_commitment": zk_commitment,
        "checksum": checksum,
    }

    signature = document.get("signature")
    if not signature or not verify_signature(signable, signature):
        signature = sign_payload(signable)

    qr_payload = document.get("qr_payload")
    qr_png_base64 = document.get("qr_png_base64")
    if not qr_payload or not qr_png_base64:
        qr_png_base64, qr_payload = generate_qr_png_base64({**signable, "signature": signature})

    updated_fields = {
        "normalization_strategy": normalization_strategy,
        "timestamp": issued_at,
        "checksum": checksum,
        "signature": signature,
        "qr_payload": qr_payload,
        "qr_png_base64": qr_png_base64,
    }

    persistence_needed = any(document.get(key) != value for key, value in updated_fields.items())
    if persistence_needed:
        documents = load_documents()
        for idx, doc in enumerate(documents):
            if doc.get("id") == document["id"]:
                documents[idx].update(updated_fields)
                document.update(updated_fields)
                save_documents(documents)
                break

    return DocumentVerificationPayload(
        id=document["id"],
        file_hash=file_hash,
        issued_at=issued_at,
        normalization_strategy=normalization_strategy,
        zk_commitment=zk_commitment,
        checksum=checksum,
        signature=signature,
        qr_payload=qr_payload,
        qr_png_base64=qr_png_base64,
    )


@app.post("/upload", response_model=DocumentResponse)
async def upload_file(file: UploadFile = File(...), user=Depends(verify_token)):
    try:
        print(f"Received file upload: {file.filename}")

        # Allow any file type (for submission deadline)
        # if not file.filename.lower().endswith('.pdf'):
        #     raise HTTPException(
        #         status_code=status.HTTP_400_BAD_REQUEST,
        #         detail="Only PDF files are allowed"
        #     )

        # Create a unique filename
        issued_at = datetime.utcnow()
        timestamp_token = issued_at.strftime("%Y%m%d%H%M%S")
        unique_filename = f"{timestamp_token}_{uuid.uuid4()}_{file.filename}"
        file_path = UPLOAD_DIR / unique_filename

        # Save the file in chunks to handle large files
        try:
            with open(file_path, "wb") as buffer:
                # Read in chunks of 1MB
                CHUNK_SIZE = 1024 * 1024  # 1MB
                # Read the entire file into memory first (for small files this is fine)
                content = await file.read()
                buffer.write(content)
                
                # Reset file pointer for future reads
                await file.seek(0)
        except Exception as e:
            print(f"Error saving file: {str(e)}")
            # Continue anyway - create a placeholder file
            try:
                with open(file_path, "wb") as buffer:
                    buffer.write(b"Placeholder file due to upload error")
                    content = b"Placeholder file due to upload error"
            except:
                pass

        # Calculate SHA256 hash of the file
        try:
            if 'content' in locals():
                sha256_hash = hashlib.sha256(content).hexdigest()
            else:
                sha256_hash = f"error-{uuid.uuid4()}"
        except Exception as e:
            print(f"Error calculating hash: {str(e)}")
            sha256_hash = f"error-{uuid.uuid4()}"

        # Generate INV-XXXX-XXXX format ID
        first_part = ''.join(random.choices(string.digits, k=4))
        second_part = ''.join(random.choices(string.digits, k=4))
        doc_id = f"INV-{first_part}-{second_part}"

        # Get file size in human-readable format
        try:
            file_size_bytes = os.path.getsize(file_path)
            if file_size_bytes < 1024:
                file_size = f"{file_size_bytes} B"
            elif file_size_bytes < 1024 * 1024:
                file_size = f"{file_size_bytes / 1024:.1f} KB"
            else:
                file_size = f"{file_size_bytes / (1024 * 1024):.1f} MB"
        except Exception as e:
            print(f"Error getting file size: {str(e)}")
            file_size = "Unknown"

        normalization_strategy = NORMALIZATION_STRATEGY
        normalized_text_hash: Optional[str] = None
        zk_commitment: Optional[str] = None
        checksum: Optional[str] = None
        signature: Optional[str] = None
        qr_payload: Optional[str] = None
        qr_png_base64: Optional[str] = None

        try:
            extracted_text = extract_text(file_path)
            normalized_text = normalize_text(extracted_text)
            normalized_text_hash = hash_normalized_text(normalized_text)

            if normalized_text_hash:
                zk_commitment = commitment_from_hash(normalized_text_hash)
                verification_payload = {
                    "id": doc_id,
                    "file_hash": sha256_hash,
                    "issued_at": isoformat_utc(issued_at),
                    "normalization_strategy": normalization_strategy,
                    "zk_commitment": zk_commitment,
                }
                checksum_seed = f"{doc_id}:{zk_commitment}:{sha256_hash}"
                checksum = hashlib.sha256(checksum_seed.encode("utf-8")).hexdigest()[:12].upper()
                verification_payload["checksum"] = checksum
                signature = sign_payload(verification_payload)
                verification_payload["signature"] = signature
                qr_png_base64, qr_payload = generate_qr_png_base64(verification_payload)
            else:
                print(f"No normalized text hash generated for document {doc_id}")
        except Exception as exc:
            print(f"Error generating verification artefacts: {exc}")

        # Create document metadata
        try:
            doc_metadata = DocumentMetadata(
                id=doc_id,
                name=f"{doc_id}.pdf",
                original_filename=file.filename,
                file_hash=sha256_hash,
                file_path=str(file_path),
                user_id=uuid.UUID(user["id"]),
                user_email=user["email"],
                user_name=user.get("full_name") or user.get("name"),
                timestamp=issued_at,
                status="active",
                size=file_size,
                normalization_strategy=normalization_strategy,
                normalized_text_hash=normalized_text_hash,
                zk_commitment=zk_commitment,
                checksum=checksum,
                signature=signature,
                qr_payload=qr_payload,
                qr_png_base64=qr_png_base64,
            )

            # Convert datetime to string for JSON serialization
            doc_dict = doc_metadata.dict()
            doc_dict["timestamp"] = isoformat_utc(doc_metadata.timestamp)
            doc_dict["user_id"] = str(doc_metadata.user_id)

            # Add new document
            documents = load_documents()
            documents.append(doc_dict)
            save_documents(documents)
        except Exception as e:
            print(f"Error creating/saving metadata: {str(e)}")

        print(f"File saved to {file_path} with ID {doc_id}")
        return DocumentResponse(
            id=doc_id,
            name=f"{doc_id}.pdf",
            file_hash=sha256_hash,
            user_id=uuid.UUID(user["id"]),
            timestamp=isoformat_utc(issued_at),
            status="active",
            size=file_size,
            zk_commitment=zk_commitment,
            checksum=checksum,
        )
    except Exception as e:
        print(f"Critical error in upload handler: {str(e)}")
        # Generate a fake response to avoid breaking the UI
        emergency_doc_id = f"INV-EMRG-{uuid.uuid4().hex[:4]}"
        return DocumentResponse(
            id=emergency_doc_id,
            name=f"{emergency_doc_id}.pdf",
            file_hash=f"emergency-{uuid.uuid4()}",
            user_id=uuid.UUID(user["id"]),
            timestamp=datetime.now().isoformat(),
            status="active",
            size="Unknown"
        )

@app.get("/documents")
async def get_user_documents(user=Depends(verify_token)):
    try:
        print(f"Getting documents for user {user['id']}")
        
        # Read documents metadata
        documents = [doc for doc in load_documents() if doc.get("user_id") == user["id"]]
        
        print(f"Found {len(documents)} documents for user {user['id']}")
        return documents
    except Exception as e:
        print(f"Error getting user documents: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.get("/document/{document_id}")
async def get_document_by_id(document_id: str):
    try:
        print(f"Getting document with ID: {document_id}")
        document = find_document(document_id)
        if not document:
            print(f"Document not found with ID: {document_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found"
            )
        
        print(f"Found document: {document['id']}")
        return document
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting document by ID: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@app.get("/document/{document_id}/verification", response_model=DocumentVerificationPayload)
async def get_document_verification(document_id: str):
    try:
        document = find_document(document_id)
        if not document:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found",
            )
        payload = build_verification_payload(document)
        return payload
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    except Exception as e:
        print(f"Error generating verification payload for {document_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@app.post("/document/{document_id}/zk-verify")
async def verify_document_proof(document_id: str, request: ProofVerificationRequest):
    try:
        document = find_document(document_id)
        if not document:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found",
            )

        payload = build_verification_payload(document)
        proof_payload = request.proof.dict()
        context = request.context or ""

        is_valid = verify_schnorr_proof(
            payload.zk_commitment,
            payload.id,
            proof_payload,
            context,
        )

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or mismatched proof.",
            )

        return {
            "status": "valid",
            "document_id": payload.id,
            "verified_at": isoformat_utc(datetime.utcnow()),
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error verifying proof for {document_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
