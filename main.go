package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// This jwk.Cache will be our global cache for Cognito's public keys.
// We'll set it up once in main().
var jwksCache *jwk.Cache

// We also need these values in our middleware, so we'll store them.
var cognitoRegion string
var cognitoUserPoolID string
var cognitoClientID string

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, loading from environment")
	}

	cognitoRegion = os.Getenv("COGNITO_REGION")
	cognitoUserPoolID = os.Getenv("COGNITO_USER_POOL_ID")
	cognitoClientID = os.Getenv("COGNITO_CLIENT_ID")

	if cognitoRegion == "" || cognitoUserPoolID == "" || cognitoClientID == "" {
		log.Fatal("Missing required Cognito env vars")
	}

	// --- JWKS Cache Setup ---
	// tell the jwx library where to find cognito public keys
	//standard URL format for all OIDC providers
	jwksURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", cognitoRegion, cognitoUserPoolID)

	// new context for cache
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create the JWK cache. This object will automatically:
	// 1. Fetch the keys from jwksURL.
	// 2. Refresh them in the background (every 15 minutes by default).
	// 3. Be thread-safe for all our API requests.
	jwksCache = jwk.NewCache(ctx)

	// Tell the cache to register the URL
	if err := jwksCache.Register(jwksURL, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil { // <-- ADDED the option here
		log.Fatalf("Failed to register JWKS URL: %v", err)
	}

	// Trigger a *first* fetch so we know it works before starting the server.
	if _, err := jwksCache.Refresh(ctx, jwksURL); err != nil {
		log.Fatalf("Failed to fetch initial JWKS: %v", err)
	}

	log.Println("Successfully fetched Cognito JWKS")
	// --- End JWKS Setup ---

	// --- Gin Server Setup ---
	r := gin.Default()

	// CORS config (same as before)
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"http://localhost:5173"}
	corsConfig.AllowHeaders = []string{"Authorization", "Content-Type"}
	r.Use(cors.New(corsConfig))

	api := r.Group("/api")
	{
		api.GET("/public", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "Hello from a public endpoint!"})
		})

		// Apply our new middleware
		api.GET("/me", authMiddleware(), func(c *gin.Context) {
			// Get the "sub" (subject) claim we stored.
			// This is the user's unique ID in Cognito.
			userID, exists := c.Get("userID")
			if !exists {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "UserID not found in context"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": fmt.Sprintf("Hello, user %s", userID),
				"userID":  userID,
			})
		})
	}

	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting server on port %s", port)
	r.Run(":" + port)
}

/**
 * authMiddleware now uses jwx to parse and validate the token.
 */
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Get the token string
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
			return
		}

		// 2. Tell the parser *where* to find the keys.
		// We point it to our global cache.
		jwksURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", cognitoRegion, cognitoUserPoolID)
		keySet, err := jwksCache.Get(c.Request.Context(), jwksURL)
		if err != nil {
			log.Printf("Failed to get JWKS from cache: %v", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to get keys"})
			return
		}

		// 3. Parse and validate the token.
		// This one call does all the work:
		// - Parses the token string
		// - Finds the correct key from the `keySet` (using the 'kid' header)
		// - Verifies the cryptographic signature

		token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keySet))
		if err != nil {
			log.Printf("Token parsing failed: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
			return
		}

		// 4. Manually validate the "claims"
		// The `jwt.Parse` only verifies the *signature*. We must
		// verify the *content* (the claims) ourselves.

		// Check 'iss' (Issuer)
		// This proves it came from our User Pool
		expectedIssuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", cognitoRegion, cognitoUserPoolID)
		if token.Issuer() != expectedIssuer {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token issuer"})
			return
		}

		// Check 'token_use'
		// This proves it's an "access" token and not an "id" token
		tokenUse, ok := token.Get("token_use")
		if !ok || tokenUse.(string) != "access" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token use"})
			return
		}

		// Check 'aud' (Audience)
		// This proves it was issued for our App Client
		// Note: Cognito access tokens call this "client_id", not "aud".
		clientID, ok := token.Get("client_id")
		if !ok || clientID.(string) != cognitoClientID {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token client_id"})
			return
		}

		// Check 'exp' (Expiration)
		// The `jwt.Parse` does this by default, but an explicit
		// check with `jwt.Validate` is good practice.
		// This verifies exp, nbf (not before), and iat (issued at).
		if err := jwt.Validate(token); err != nil {
			log.Printf("Token validation failed: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token validation failed", "details": err.Error()})
			return
		}

		// 5. Success! Store the user's ID (the 'sub' claim) in the context.
		c.Set("userID", token.Subject())

		// Continue to the next handler
		c.Next()
	}
}
