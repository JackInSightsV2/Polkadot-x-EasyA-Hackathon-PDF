// API service for handling all requests to the backend
import fetchWrapper from './fetchWrapper';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface LoginData {
  email: string;
  password: string;
}

export interface SignupData {
  name: string;
  email: string;
  password: string;
  companyName?: string;
  registeredAddress?: string;
  companyId?: string;
}

export interface CompanyData {
  id: string;
  name: string;
  email: string;
  registeredAddress?: string;
  createdAt: string;
  updatedAt: string;
  token?: string;
}

export interface UserData {
  id: string;
  fullName: string;
  email: string;
  companyId: string;
  token?: string;
}

export interface DocumentVerificationPayload {
  id: string;
  file_hash: string;
  issued_at: string;
  normalization_strategy: string;
  zk_commitment: string;
  checksum: string;
  signature: string;
  qr_payload: string;
  qr_png_base64: string;
}

export interface SchnorrProof {
  rx: string;
  ry: string;
  s: string;
}

export interface ProofVerificationResponse {
  status: string;
  document_id: string;
  verified_at: string;
}

export interface ProofVerificationRequest {
  proof: SchnorrProof;
  context?: string;
}

// Authentication API functions
export const authAPI = {
  // Register company
  async registerCompany(data: { name: string, email: string, password: string, registeredAddress?: string }) {
    console.log('Registering company:', data.email);
    const response = await fetchWrapper.post<CompanyData>('/register/company', data);
    console.log('Company registration response:', response);
    return response;
  },

  // Login company
  async loginCompany(data: LoginData) {
    console.log('Logging in company:', data.email);
    const response = await fetchWrapper.post<CompanyData>('/login/company', null, {
      params: {
        email: data.email,
        password: data.password
      }
    });
    console.log('Company login response:', response);
    return response;
  },

  // Register user
  async registerUser(data: { fullName: string, email: string, companyId: string, password: string }) {
    console.log('Registering user:', data.email);
    const response = await fetchWrapper.post<UserData>('/register/user', data);
    console.log('User registration response:', response);
    return response;
  },

  // Login user
  async loginUser(data: LoginData) {
    console.log('Logging in user:', data.email);
    const response = await fetchWrapper.post<UserData>('/login/user', data);
    console.log('User login response:', response);
    return response;
  },
};

// User/profile API functions
export const userAPI = {
  // Get user profile
  async getProfile(token: string) {
    console.log('Getting user profile with token');
    const response = await fetchWrapper.get('/protected', { token });
    console.log('User profile response:', response);
    return response;
  },
}; 

export const documentAPI = {
  async getVerification(documentId: string) {
    return fetchWrapper.get<DocumentVerificationPayload>(`/document/${documentId}/verification`);
  },

  async verifyProof(documentId: string, payload: ProofVerificationRequest) {
    return fetchWrapper.post<ProofVerificationResponse>(`/document/${documentId}/zk-verify`, payload);
  },
};