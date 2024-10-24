import { OAuthManagerProps, AccessTokenRequestBody, TokenResponse, ResponseType } from './types';
import { TokenStorage } from './storage';
import crypto from 'crypto';

/**
 * OAuthManager class to handle OAuth2 and OpenID Connect authentication.
 */
export class OAuthManager {
    private clientId: string;
    private clientSecret: string;
    private redirectUri: string;
    private scope: string;
    private state: string;
    private responseType: ResponseType;
    private storage: TokenStorage;
    private authUrl: string;
    private tokenUrl: string;
    private revokeUrl: string;
    private userInfoUrl: string;
    private accessToken: string | null = null;
    private refreshToken: string | null = null;
    private expiry: number | null = null;
    private idToken: string | null = null;
    private hmacSecret: string | null = null;

    /**
     * Constructor for OAuthManager.
     * @param props - OAuthManager properties.
     * @param storage - Storage instance to handle token storage.
     * @param hmacSecret - Optional HMAC secret for signing requests.
     */
    constructor(props: OAuthManagerProps, storage: TokenStorage, hmacSecret?: string) {
        this.clientId = props.clientId;
        this.clientSecret = props.clientSecret;
        this.redirectUri = props.redirectUri;
        this.scope = props.scope;
        this.state = props.state;
        this.responseType = props.responseType || 'code';
        this.storage = storage;
        this.authUrl = props.authUrl || 'https://api.beyondigital.in/o/authorize';
        this.tokenUrl = props.tokenUrl || 'https://api.beyondigital.in/o/token';
        this.revokeUrl = props.revokeUrl || 'https://api.beyondigital.in/o/revoke-token';
        this.userInfoUrl = props.userInfoUrl || 'https://api.beyondigital.in/o/userinfo';
        this.hmacSecret = hmacSecret || null;

        this.loadTokens();
    }

    /**
     * Load tokens from storage.
     */
    private loadTokens(): void {
        this.accessToken = this.storage.get('access_token');
        this.refreshToken = this.storage.get('refresh_token');
        this.expiry = parseInt(this.storage.get('expiry') ?? '0');
        this.idToken = this.storage.get('id_token');
    }

    /**
     * Save tokens to storage.
     */
    private saveTokens(data: TokenResponse): void {
        this.accessToken = data.access_token;
        this.refreshToken = data.refresh_token || null;
        this.expiry = data.expires_in ? Date.now() + data.expires_in * 1000 : null;
        this.idToken = data.id_token || null;

        this.storage.set('access_token', this.accessToken);
        if (this.refreshToken) {
            this.storage.set('refresh_token', this.refreshToken);
        }
        if (this.expiry) {
            this.storage.set('expiry', String(this.expiry));
        }
        if (this.idToken) {
            this.storage.set('id_token', this.idToken);
        }
    }

    /**
     * Clear all tokens from storage.
     */
    private clearTokens(): void {
        this.accessToken = null;
        this.refreshToken = null;
        this.expiry = null;
        this.idToken = null;

        this.storage.remove('access_token');
        this.storage.remove('refresh_token');
        this.storage.remove('expiry');
        this.storage.remove('id_token');
    }

    /**
     * Get the authorization URL.
     * @returns The authorization URL.
     */
    getAuthorizationUrl(): string {
        const params = new URLSearchParams({
            response_type: this.responseType,
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            scope: this.scope,
            state: this.state
        });
        return `${this.authUrl}?${params.toString()}`;
    }

    /**
     * Generate HMAC signature.
     * @param data - The data to be signed.
     * @returns The HMAC signature.
     */
    private generateHmacSignature(data: string): string {
        if (!this.hmacSecret) {
            throw new Error('HMAC secret is not provided');
        }
        return crypto.createHmac('sha256', this.hmacSecret).update(data).digest('hex');
    }

    /**
     * Fetch the access token using the authorization code.
     * @param code - The authorization code.
     */
    async fetchToken(code: string): Promise<void> {
        const body: AccessTokenRequestBody = {
            grant_type: 'authorization_code',
            code,
            redirect_uri: this.redirectUri,
            client_id: this.clientId,
            client_secret: this.clientSecret
        };

        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (this.hmacSecret) {
            headers['X-HMAC-Signature'] = this.generateHmacSignature(JSON.stringify(body));
        }

        const response = await fetch(this.tokenUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
        });

        const data: TokenResponse = await response.json();
        this.saveTokens(data);
    }

    /**
     * Refresh the access token using the refresh token.
     */
    async refreshAccessToken(): Promise<void> {
        if (!this.refreshToken) {
            throw new Error('No refresh token available');
        }

        const body = {
            grant_type: 'refresh_token',
            refresh_token: this.refreshToken,
            client_id: this.clientId,
            client_secret: this.clientSecret
        };

        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (this.hmacSecret) {
            headers['X-HMAC-Signature'] = this.generateHmacSignature(JSON.stringify(body));
        }

        const response = await fetch(this.tokenUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
        });

        const data: TokenResponse = await response.json();
        this.saveTokens(data);
    }

    /**
     * Revoke the access token.
     */
    async revokeToken(): Promise<void> {
        if (!this.accessToken) {
            throw new Error('No access token available');
        }

        const body = { token: this.accessToken };
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (this.hmacSecret) {
            headers['X-HMAC-Signature'] = this.generateHmacSignature(JSON.stringify(body));
        }

        await fetch(this.revokeUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
        });
        this.clearTokens();
    }

    /**
     * Fetch user information using the access token.
     * @returns The user information.
     */
    async fetchUserInfo(): Promise<any> {
        if (!this.accessToken) {
            throw new Error('No access token available');
        }

        const headers: Record<string, string> = { 'Authorization': `Bearer ${this.accessToken}` };
        if (this.hmacSecret) {
            headers['X-HMAC-Signature'] = this.generateHmacSignature(this.accessToken);
        }

        const response = await fetch(this.userInfoUrl, { headers });
        return response.json();
    }
}
