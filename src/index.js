import CryptoJS from "crypto-js";

const __DEV__ = true;

const baseURL = __DEV__
	? "http://jae.local:8000/"
	: "https://api.beyondigital.in/";
const _authorizeURL = baseURL + "o/authorize/";
const _tokenURL = baseURL + "o/token/";
const _revokeURL = baseURL + "o/revoke-token/";
const _refreshURL = baseURL + "o/token/";
const _infoURL = baseURL + "o/userinfo/";

/**
 * Storage class for storing access token.
 *
 * @class Storage: Storage class for storing all necessary data
 * @param {Storage} storage: Storage object to store access token
 * @returns {Storage} Storage object
 * @example
 * const storage = new Storage();
 * storage.set("key", "value");
 * storage.get("key");
 * storage.remove("key");
 *
 * @throws {Error} Error: <error>
 * @throws {TypeError} Failed to fetch
 *
 * @todo Implement storage for access token
 *
 * Can be implemented using localStorage or sessionStorage or IndexedDB
 * Methods to implement:
 * - set(key, value): Set value for key
 * - get(key): Get value for key
 * - remove(key): Remove value for key
 *
 */

class Storage {
	constructor() {
		this.storage = window.localStorage;
	}

	set(key, value) {
		this.storage.setItem(key, value);
	}

	get(key) {
		return this.storage.getItem(key);
	}

	remove(key) {
		this.storage.removeItem(key);
	}
}

/**
 * OAuthManager class for managing OAuth authentication flow.
 *
 * @class OAuthManager: OAuthManager class for managing OAuth authentication flow
 * @param {string} clientID: OAuth client ID
 * @param {string} redirectURI: OAuth redirect URI
 * @param {string} scope: OAuth scope
 * @param {string} responseType: OAuth response type
 * @param {Storage} storage: Storage object to store access token
 * @param {function} openWindow: Function to open new window, should return code/token from URL and have close method
 * @param {Crypto} crypto: Crypto object for generating PKCE code
 * @returns {OAuthManager} OAuthManager object
 *
 *
 * @example
 * const oauth = new OAuthManager(clientID, redirectURI, scope, responseType, storage);
 * oauth.authorize();
 * oauth.getAccessToken(code);
 * oauth.refreshToken();
 * oauth.revokeToken();
 *
 * @throws {Error} clientID and redirectURI are required
 * @throws {Error} No access token found
 * @throws {Error} Error: <error>
 * @throws {TypeError} Failed to fetch
 *
 */
class OAuthManager {
	/**
	 * Creates an instance of OAuthManager.
	 */
	init({
		clientId,
		redirectURI,
		withPKCE = true,
		scope = undefined,
		responseType = "authorization_code",
		openWindow = undefined,
		storage = new Storage(),
		infoURL = _infoURL,
		tokenURL = _tokenURL,
		revokeURL = _revokeURL,
		refreshURL = _refreshURL,
		authorizeURL = _authorizeURL,
	}) {
		if (clientId === "" || redirectURI === "") {
			throw new Error("clientID and redirectURI are required");
		}
		// this.crypto = CryptoJS();
		this.clientID = clientId;
		this.redirectURI = redirectURI;
		this.scope = scope;
		this.authorizeURL = authorizeURL;
		this.tokenURL = tokenURL;
		this.revokeURL = revokeURL;
		this.refreshURL = refreshURL;
		this.responseType =
			responseType === "authorization_code" ? "code" : responseType;
		this.storage = storage;
		this.openWindow = openWindow;
		this.infoURL = infoURL;
		this.withPKCE = withPKCE;
		this.accessToken = this.storage.get("access_token", null);
		this.refreshToken = this.storage.get("refresh_token", null);
		this.clientHeader = new Headers({
			"Content-Type": "application/x-www-form-urlencoded",
			Authorization: "Bearer " + this.accessToken,
		});
	}

	getAccessToken(code) {
		// grant_type=authorization_code&
		// code=Pf04q5iSzCr6w3jeOJkMjX3oRNKLbZ&
		// redirect_uri=https%3A%2F%2Fwww.getpostman.com%2Foauth2%2Fcallback&
		// code_verifier=0zFgJYnDwMzQTAX_YL45p5_dBurXBr_L9mNukhs9aBY&
		// client_id=EXPO_TEST_KEY
		const headers = new Headers();
		headers.append("Accept", "*/*");
		headers.append("Content-Type", "application/x-www-form-urlencoded");
		const data = {
			client_id: this.clientID,
			redirect_uri: this.redirectURI,
			grant_type: "authorization_code",
			code: code,
			code_verifier: this.codeVerifier,
		};

		const body = Object.keys(data)
			.map(
				(key) => encodeURIComponent(key) + "=" + encodeURIComponent(data[key])
			)
			.join("&");
		fetch(this.tokenURL, {
			method: "POST",
			headers,
			body,
		})
			.then((response) => response.json())
			.then((data) => {
				this.accessToken = data.access_token;
				this.refreshToken = data.refresh_token;
				this.storage.set("expires_in", data.expires_in);
				this.storage.set("expiry", data.expires_in + new Date().getTime());
				this.storage.set("access_token", this.accessToken);
				this.storage.set("refresh_token", this.refreshToken);
				if (__DEV__) {
					console.log("Access Token:", this.accessToken);
					console.log("Refresh Token:", this.refreshToken);
					console.log("Expires In:", data.expires_in);
					console.log("data", data);
				}
			})
			.catch((error) => console.error("Error:", error));
	}

	authorize() {
		const url = new URL(this.authorizeURL);
		url.searchParams.append("client_id", this.clientID);
		url.searchParams.append("redirect_uri", this.redirectURI);
		url.searchParams.append("response_type", this.responseType);
		if (this.scope) {
			url.searchParams.append("scope", this.scope);
		}
		if (this.withPKCE) {
			// Generate PKCE code verifier and challenge
			this.codeVerifier = this.generateRandomString(64);
			const codeChallenge = this.sha256(this.codeVerifier);
			this.storage.set("code_verifier", this.codeVerifier);
			url.searchParams.append("code_challenge", codeChallenge);
			url.searchParams.append("code_challenge_method", "S256");
		}
		// open new window to authorize and get code
		if (
			this.openWindow === undefined ||
			(this.openWindow === null && window !== undefined)
		) {
			// Open a new window for the OAuth flow
			const authWindow = window.open(url, "authPopup", "width=600,height=600");

			// Check if the popup was successfully opened
			if (!authWindow) {
				alert(
					"Unable to open authentication window. Please check your popup settings."
				);
				return;
			}

			// Function to check the URL of the popup
			const checkPopupUrl = () => {
				console.log("Checking popup URL", authWindow.window.location);
				try {
					// If the popup has been closed, stop checking
					if (authWindow.closed) {
						clearInterval(checkInterval);
						return;
					}

					// Check if the popup has navigated to the redirect URI
					const popupUrl = authWindow.window.location.href;
					console.log("Popup URL:", popupUrl);
					if (popupUrl.startsWith(this.redirectURI)) {
						clearInterval(checkInterval);
						const urlParams = new URLSearchParams(
							authWindow.window.location.search
						);
						const code = urlParams.get("code"); // Assuming the code is passed as a URL parameter
						console.log("Popup URL:", popupUrl);

						if (code) {
							console.log("OAuth code:", code);
							// Proceed to exchange the code for an access token
							this.getAccessToken(code);
						}

						// Close the popup window
						authWindow.close();
					}
				} catch (error) {
					// Errors are expected if the popup navigates to a URL outside of our control due to same-origin policy
					console.error("Error checking popup URL:", error);
				}
			};

			// Start checking the popup URL every 500 milliseconds
			const checkInterval = setInterval(checkPopupUrl, 500);
		} else if (typeof this.openWindow === "function") {
			try {
				// listen for change in url and get code
				const code = this.openWindow(url.href);
				if (code) {
					this.getAccessToken(code);
					code.close();
				}
			} catch (e) {
				console.error(e);
				code.close();
			}
		} else {
			throw new Error("openWindow is not a function");
		}
	}

	refreshToken() {
		// Implement token refresh logic here
		if (!this.accessToken) {
			this.authorize();
		}
		const data = {
			client_id: this.clientID,
			grant_type: "refresh_token",
			refresh_token: this.refreshToken,
		};
		fetch(this.refreshURL, {
			method: "POST",
			headers: this.clientHeader,
			body: JSON.stringify(data),
		})
			.then((response) => response.json())
			.then((data) => {
				this.accessToken = data.access_token;
				this.storage.set("access_token", this.accessToken);
			})
			.catch((error) => console.error("Error:", error));
	}

	revokeToken() {
		// Implement token revocation logic here
		if (!this.accessToken) {
			throw new Error("No access token found");
		}
		const data = {
			client_id: this.clientID,
			token: this.accessToken,
		};
		fetch(this.revokeURL, {
			method: "POST",
			headers: this.clientHeader,
			body: JSON.stringify(data),
		})
			.then((response) => response.json())
			.then((data) => {
				this.accessToken = null;
				this.refreshToken = null;
				this.storage.remove("access_token");
				this.storage.remove("refresh_token");
			})
			.catch((error) => console.error("Error:", error));
	}

	isTokenValid() {
		// Implement token validation logic here
		const expiresIn = this.storage.get("expires_in");
		if (!expiresIn) {
			return false;
		}
		const now = new Date().getTime();
		return now < expiresAt;
	}

	getUserInfo() {
		// Implement user info logic here
		if (!this.accessToken) {
			throw new Error("No access token found");
		}
		fetch(this.infoURL, {
			method: "GET",
			headers: {
				"Content-Type": "application/json",
				Authorization: "Bearer " + this.storage.get("access_token"),
			},
		})
			.then((response) => response.json())
			.then((data) => {
				if (__DEV__) {
					console.log("User Info:", data);
				}
				return data;
			})
			.catch((error) => console.error("Error:", error));
	}

	// PKCE functions
	generateRandomString(length) {
		const charset =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"; // available characters
		let random = "";
		for (let i = 0; i < length; i++) {
			random += charset.charAt(Math.floor(Math.random() * charset.length));
		}
		return random;
	}

	sha256(plain) {
		try {
			return CryptoJS.SHA256(plain).toString(CryptoJS.enc.Base64url);
		} catch (e) {
			console.error(e);
			throw new Error("Crypto API not available", this.crypto);
		}
	}

	// generate coode verifier for oauth with PKCE to access token
	generateCodeVerifier(code) {
		const codeVerifier = this.storage.get("code_verifier");
		if (!codeVerifier) {
			throw new Error("Code verifier not found");
		}
		return codeVerifier;
	}

	// Implement API call logic here
	// auto wrap all function calls with this function
}

if (window !== undefined) {
	window.OAuthManager = OAuthManager;
}
// export default OAuthManager;
