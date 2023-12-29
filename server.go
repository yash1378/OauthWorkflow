package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"net/http"
)

type UserInfo struct {
	Sub      string `json:"sub"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Picture  string `json:"picture"`
	Provider string `json:"iss"`
}

func main() {
	const googleClientId = process.env.GOOGLE_CLIENT_ID;
	const googleClientSecret = process.env.GOOGLE_SECRET;
	redirectURL := "http://localhost:3001/api/auth/google/callback"

	oauth2Config := &oauth2.Config{
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"profile", "email"},
		Endpoint:     google.Endpoint,
	}

	router := gin.Default()

	router.GET("/api/auth/google", func(c *gin.Context) {
		authURL := oauth2Config.AuthCodeURL("state")
		c.Redirect(302, authURL)
	})

	router.GET("/api/auth/google/callback", func(c *gin.Context) {
		code := c.Query("code")

		// Exchange the authorization code for tokens
		token, err := oauth2Config.Exchange(c, code)
		if err != nil {
			c.String(500, "Failed to exchange token")
			return
		}

		// Use the access token to fetch user information
		userInfo, err := getUserInfo(token.AccessToken)
		if err != nil {
			c.String(500, "Failed to fetch user information")
			return
		}

		c.String(200, fmt.Sprintf("Token exchanged successfully. User: %+v", userInfo))
	})

	router.Run(":3001")
}

// Function to fetch user information from Google using the access token
func getUserInfo(accessToken string) (*UserInfo, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo UserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return nil, err
	}

	return &userInfo, nil
}
