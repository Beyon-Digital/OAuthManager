import * as CryptoJS from "crypto-js";

const __DEV__: boolean = process.env.NODE_ENV === "development";

const baseURL = __DEV__
	? "http://localhost:8000/"
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
 * - set(key: string, value: any): Set value for key
 * - get(key: string): Get value for key
 * - remove(key: string): Remove value for key
 *
 */

class Storage {
	/**
	 * Creates an instance of Storage.
	 */

	storage: any;

	constructor() {
		this.storage = window.localStorage;
	}

	set(key: string, value: any) {
		this.storage.setItem(key, value);
	}

	get(key: string) {
		return this.storage.getItem(key);
	}

	remove(key: string) {
		this.storage.removeItem(key);
	}
};

type ResponseType = 'authorization_code' | 'token' | 'code';

type AccessTokenRequestBody = {
	code?: string;
	code_verifier?: string;
	grant_type: ResponseType;
	redirect_uri: string;
	client_id: string;
};

interface OAuthManagerProps {
	clientID: string;
	redirectURI: string;
	scope: string;
	responseType: ResponseType;
	authorizeURL: string;
	tokenURL: string;
	revokeURL: string;
	refreshURL: string;
	infoURL: string;
	accessToken: string;
	refreshToken: string;
	clientHeader: Headers;
	storage: Storage;
	openWindow?: (url: string) => string;
	codeVerifier: string;
	withPKCE: boolean;
};


/**
 * OAuthManager class for managing OAuth authentication flow.
 *
 * @class OAuthManager: OAuthManager class for managing OAuth authentication flow
 * @param {string} clientID: OAuth client ID
 * @param {string} redirectURI: OAuth redirect URI
 * @param {string} scope: OAuth scope
 * @param {string} responseType: OAuth response type
 * @param {Storage} storage: Storage object to store access token
 * @param {function} openWindow: Function to open new window, should return code/token from URL after OAuth flow
 * @param {Crypto} crypto: Crypto object for generating PKCE code
 * @returns {OAuthManager} OAuthManager object
 *
 *
 * @example
 * const oauth = new OAuthManager(clientID, redirectURI, scope, responseType, storage);
 * oauth.authorize();
 * oauth.getAccessTokenFromCode(code);
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

	clientID: string;
	redirectURI: string;
	scope: string;
	responseType: 'authorization_code' | 'token' | 'code';
	authorizeURL: string;
	tokenURL: string;
	revokeURL: string;
	refreshURL: string;
	infoURL: string;
	accessToken: string;
	refreshToken: string;
	clientHeader: Headers;
	storage: Storage;
	openWindow?: (url: string) => string;
	codeVerifier: string;
	withPKCE: boolean;


	init({
		clientID,
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
	}: OAuthManagerProps) {
		if (clientID === "" || redirectURI === "") {
			throw new Error("clientID and redirectURI are required");
		}
		if (!openWindow && window === undefined) {
			throw new Error("window is not available and openWindow is not provided! Please provide openWindow function to open new window for OAuth flow");
		}
		this.clientID = clientID;
		this.redirectURI = redirectURI;
		this.scope = Array.isArray(scope) ? scope.join(" ") : scope;
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
		this.accessToken = this.storage.get("access_token");
		this.refreshToken = this.storage.get("refresh_token");
		this.clientHeader = new Headers({
			"Content-Type": "application/x-www-form-urlencoded",
			Authorization: "Bearer " + this.accessToken,
		});
	}

	getAccessTokenFromCode(code: string) {
		const headers = new Headers();
		headers.append("Accept", "*/*");
		headers.append("Content-Type", "application/x-www-form-urlencoded");
		const data: AccessTokenRequestBody = {
			client_id: this.clientID,
			redirect_uri: this.redirectURI,
			grant_type: this.responseType === "code" ? "authorization_code" : "token",
			code: code
		};

		if (this.withPKCE) {
			data['code_verifier'] = this.codeVerifier;
		}

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
				this.storage.set("expires_at", data.expires_in + new Date().getTime());
				this.storage.set("access_token", this.accessToken);
				this.storage.set("refresh_token", this.refreshToken);
				if (__DEV__) {
					console.log("Access Token:", this.accessToken);
					console.log("Refresh Token:", this.refreshToken);
					console.log("Expires In:", data.expires_in);
					console.log("data", data);
				}
			})
			.catch((error) => console.error("Error: ", error));
	}

	logout() {
		this.revokeToken();
		this.storage.remove("access_token");
		this.storage.remove("refresh_token");
		this.storage.remove("expires_in");
		this.storage.remove("expires_at");
	}

	login() {
		return new Promise((resolve, reject) => {
			try {
				this.authorize();
				const userinfo = this.getUserInfo()
					.then((res) => res)
					.catch(reject);
				resolve(
					Object.assign({}, userinfo ?? {}, {
						access_token: this.accessToken,
						refresh_token: this.refreshToken,
						expires_at: this.storage.get("expires_at"),
						expires_in: this.storage.get("expires_in"),
					})
				);
			} catch (error) {
				return reject(error);
			}
		});
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

		// Open a new window for the OAuth flow and get code
		// -------------------- OR --------------------------------
		// open new window to authorize and get code
		if (
			this.openWindow === undefined ||
			(this.openWindow === null && window !== undefined)
		) {
			// Open a new window for the OAuth flow
			const authWindow = window.open(url, "popup", "width=600,height=600");

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
							this.getAccessTokenFromCode(code);
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
					this.getAccessTokenFromCode(code);
				}
			} catch (e) {
				console.error(e);
			}
		} else {
			throw new Error("openWindow is not a function");
		}
	}

	tokenRefresh() {
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
		const expiresAt = this.storage.get("expires_at");
		if (!expiresAt) {
			return false;
		}
		const now = new Date().getTime();
		return now < expiresAt;
	}

	async getUserInfo() {
		// Implement user info logic here
		if (!this.isTokenValid()) {
			throw new Error("No access token found");
		}
		if (!this.accessToken) {
			throw new Error("No access token found");
		}
		try {
			const response = await fetch(this.infoURL, {
				method: "GET",
				headers: {
					"Content-Type": "application/json",
					Authorization: "Bearer " + this.storage.get("access_token"),
				},
			});
			const data = await response.json();
			if (__DEV__) {
				console.log("User Info:", data);
			}
			return data;
		} catch (error) {
			console.error("Error:", error);
			return { error: error };
		}
	}

	// PKCE functions
	generateRandomString(length: number) {
		const charset =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"; // available characters
		let random = "";
		for (let i = 0; i < length; i++) {
			random += charset.charAt(Math.floor(Math.random() * charset.length));
		}
		return random;
	}

	sha256(plain: string | CryptoJS.lib.WordArray) {
		try {
			return CryptoJS.SHA256(plain).toString(CryptoJS.enc.Base64url);
		} catch (e) {
			console.error(e);
			throw new Error("Crypto API not available", this.crypto);
		}
	}

	// Implement API call logic here
	// auto wrap all function calls with this function
}


declare global {
	interface Window {
		OAuthManager: typeof OAuthManager;
	}
}
if (window !== undefined) {
	window.OAuthManager = OAuthManager;
}

export default OAuthManager;
