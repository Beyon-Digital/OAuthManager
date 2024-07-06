# BD-OAuth Library

Welcome to the BD-OAuth Library documentation! This library is an open OAuth 2.0 implementation with OpenID Connect (OIDC) compliance, designed to help you authenticate users with Beyond Digital's Single Sign-On (SSO) service. Whether you're a seasoned developer or just starting out, this guide will help you integrate BD-OAuth into your project with ease.

## Getting Started

Integrating BD-OAuth into your project is straightforward. You can either include it directly in your HTML using a `<script>` tag or install it via npm for use in a Node.js project.

### Option 1: Including Directly in HTML

To use BD-OAuth directly in your HTML pages, simply include the following `<script>` tag in the `<head>` section of your HTML document:

```html
<script src="https://beyondigital.in/o/script.js"></script>
<script>
const bdAuth = new OAuthManager();
bdAuth.init({
    clientId: "YOUR_CLIENT_ID",
    redirectURI: "YOUR_REDIRECT_URI",
    responseType: "authorization_code",
    scopes: ["openid", "profile", "email", "YOUR_ALLOWED_SCOPE"],
    withPKCE: true,
});
bdAuth.authorize();
</script>
```

This method is the easiest way to get started and is perfect for simple projects or for learning purposes.


### Option 2: Installing via NPM

For more complex projects or if you're using a build system, you might prefer to install BD-OAuth via npm. This approach allows you to `require` or `import` BD-OAuth in your JavaScript files.

Run the following command in your project directory:

```bash
npm install bd-oauth
```

Once installed, you can import BD-OAuth in your JavaScript files like this:

```javascript
const BD_OAuth = require('bd-oauth');
```

or

```javascript
import BD_OAuth from 'bd-oauth';
```

## Usage

After including BD-OAuth in your project, you can start using it to authenticate users. Here's a basic example:

Storage class should be implemented by the user to store the token and user details. The class should have the following methods

```typescript
class Storage {
    setItem(key: string, value: string): void;
    getItem(key: string): string | null;
    removeItem(key: string): void;
}
```

```javascript
const bdOAuth = new OAuthManager(); // Create a new instance of the OAuthManager class (use OAuthManager for web and default export for node)

bdOAuth.init({
    clientId: 'YOUR_CLIENT_ID',
    redirectUri: 'YOUR_REDIRECT_URI',
    scopes: ['openid', 'profile', 'email'],
    responseType: 'authorization_code', // optional, default is 'code' ['authorization_code', 'code, 'token', 'id_token']
    withPKCE: true // optional, default is true for enhanced security,
    storage: Storage // optional, default is window.localStorage (for web) if not available will be required to pass
});

// Log in the user using the OAuth 2.0 authorization code flow
bdOAuth.authorize()

// Log in the user using the OAuth 2.0 flow and get the access token and user details
bdOAuth.login()
    .then(user => {
        console.log('User authenticated', user);
    })
    .catch(error => {
        console.error('Authentication failed', error);
    });

// Log out the user
bdOAuth.logout();

// Get user details
bdOAuth.getUser()
    .then(user => {
        console.log('User details', user);
    })
    .catch(error => {
        console.error('Failed to get user details', error);
    });

// Check if the user is authenticated
bdOAuth.isTokenValid();

// refresh the token
bdOAuth.tokenRefresh()
```

### Configuration

Replace YOUR_CLIENT_ID and YOUR_REDIRECT_URI with the values provided by Beyond Digital when you register your application.

Support
If you encounter any issues or have questions, please feel free to open an issue on our GitHub repository.

Contributing
Contributions are welcome! If you'd like to contribute, please fork the repository and submit a pull request.

License
BD-OAuth is licensed under the ISC license. See the LICENSE file for more details.
