export type ResponseType = 'authorization_code' | 'token' | 'code' | 'id_token';

export type AccessTokenRequestBody = {
    grant_type: string;
    code: string;
    redirect_uri: string;
    client_id: string;
    client_secret: string;
};

export interface OAuthManagerProps {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    scope: string;
    state: string;
    authUrl?: string;
    tokenUrl?: string;
    revokeUrl?: string;
    userInfoUrl?: string; // For OpenID Connect
    responseType?: ResponseType;
    refreshToken: string | null;
    expiry: number | null;
    idToken: string | null;
}

export interface TokenResponse {
    access_token: string;
    id_token?: string; // For OpenID Connect
    refresh_token?: string;
    expires_in?: number;
    token_type?: string;
}
