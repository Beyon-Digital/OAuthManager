# Beyond Digital's OAuth2 Library

A cross-platform client-side OAuth2 management library in TypeScript.

## Installation

To install the package, run:

```sh
npm install bd-oauth
```

## Usage

### Importing the Library

First, import the necessary classes from the library:

```typescript
import { OAuthManager } from './oauthManager';
import { LocalStorage } from './storage'; // Assume LocalStorage implements TokenStorage interface
```

### Creating an Instance of OAuthManager

Create an instance of `OAuthManager` with the required properties and a storage instance:

```typescript
const oauthManager = new OAuthManager({
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    redirectUri: 'your-redirect-uri',
    scope: 'openid profile email',
    state: 'random-state',
    responseType: 'code', // or 'token', 'id_token'
    authUrl: 'https://authorization-server.com/oauth/authorize',
    tokenUrl: 'https://authorization-server.com/oauth/token',
    revokeUrl: 'https://authorization-server.com/oauth/revoke',
    userInfoUrl: 'https://authorization-server.com/oauth/userinfo'
}, new LocalStorage());
```

### Getting the Authorization URL

To get the authorization URL, use the `getAuthorizationUrl` method:

```typescript
const authUrl = oauthManager.getAuthorizationUrl();
console.log('Authorization URL:', authUrl);
```

### FETCHING TOKENS

 Fetching Tokens

To fetch tokens using an authorization code, use the `fetchToken` method:

```typescript
oauthManager.fetchToken('authorization-code-here').then(() => {
    console.log('Token fetched and saved.');
});
```

### Refreshing Tokens

To refresh tokens using a refresh token, use the `refreshToken` method:

```typescript
oauthManager.refreshToken('refresh-token-here').then(() => {
    console.log('Token refreshed and saved.');
});
```

### Revoking Tokens

To revoke a token, use the `revokeToken` method:

```typescript
oauthManager.revokeToken('token-to-revoke');
console.log('Token revoked.');
```

### FETCHING USER INFORMATION

 Fetching User Information

To fetch user information using the access token, use the `fetchUserInfo` method:

```typescript
oauthManager.fetchUserInfo().then(userInfo => {
    console.log('User Info:', userInfo);
});
```

## Example

Here is a complete example of how to use the `OAuthManager`:

```typescript
import { OAuthManager } from './oauthManager';
import { LocalStorage } from './storage'; // Assume LocalStorage implements TokenStorage interface

const oauthManager = new OAuthManager({
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret',
    redirectUri: 'your-redirect-uri',
    scope: 'openid profile email',
    state: 'random-state',
    responseType: 'code', // or 'token', 'id_token'
    authUrl: 'https://authorization-server.com/oauth/authorize',
    tokenUrl: 'https://authorization-server.com/oauth/token',
    revokeUrl: 'https://authorization-server.com/oauth/revoke',
    userInfoUrl: 'https://authorization-server.com/oauth/userinfo'
}, new LocalStorage());

// Get authorization URL
const authUrl = oauthManager.getAuthorizationUrl();
console.log('Authorization URL:', authUrl);

// Fetch token using authorization code
oauthManager.fetchToken('authorization-code-here').then(() => {
    console.log('Token fetched and saved.');
});

// Refresh token
oauthManager.refreshToken('refresh-token-here').then(() => {
    console.log('Token refreshed and saved.');
});

// Revoke token
oauthManager.revokeToken('token-to-revoke');
console.log('Token revoked.');

// Fetch user info
oauthManager.fetchUserInfo().then(userInfo => {
    console.log('User Info:', userInfo);
});
```

This setup provides a structured and modular approach to building a cross-platform client-side OAuth2 management library in TypeScript.

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## Author

This library is maintained by [founder@beyondigital](mailto:founder@beyondigital.in).

This README provides a comprehensive guide on how to use the OAuth2 library, including installation, usage, and examples.
