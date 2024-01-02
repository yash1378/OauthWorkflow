package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
)

type UserInfo struct {
	Sub      string `json:"sub"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Picture  string `json:"picture"`
	Provider string `json:"iss"`
}

type Info struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

var (
	a     = 1
	aLock sync.Mutex
)

func main() {
	googleClientId := "864056163165-6kc1aphrn4hkb28rdb2b0fvr99psnpao.apps.googleusercontent.com"
	googleClientSecret := "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"
	redirectURL := "http://localhost:3001/api/auth/google/callback"

	client := redis.NewClient(&redis.Options{
		Addr:     "redis-18627.c305.ap-south-1-1.ec2.cloud.redislabs.com:18627",
		Password: "98O8Uq038XwQaMygjKb1JlWBIQm5v6QE", // no password set
		DB:       0,  // use default DB
	})

	oauth2Config := &oauth2.Config{
		ClientID:     googleClientId,
		ClientSecret: googleClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"profile", "email"},
		Endpoint:     google.Endpoint,
	}

	router := gin.Default()

	// consent screen 

	router.GET("/api/auth/google", func(c *gin.Context) {
		authURL := oauth2Config.AuthCodeURL("state")
		c.Redirect(302, authURL)
	})

	// callback url on which data is sent by google 

	router.GET("/api/auth/google/callback", func(c *gin.Context) {
		code := c.Query("code")

		// Use goroutines to handle token exchange and user information fetching concurrently
		ch := make(chan *UserInfo)
		errCh := make(chan error)

		go func() {
			// Exchange the authorization code for tokens
			token, err := oauth2Config.Exchange(c, code)
			if err != nil {
				errCh <- err
				return
			}

			// Use the access token to fetch user information
			userInfo, err := getUserInfo(token.AccessToken)
			if err != nil {
				errCh <- err
				return
			}

			ch <- userInfo
		}()

		select {
		case userInfo := <-ch:
			aLock.Lock()
			defer aLock.Unlock()

			// Storing Info in Redis
			var info Info
			info.Email = userInfo.Email
			info.Name = userInfo.Name
			jsonData, err := json.Marshal(info)
			if err != nil {
				panic(err)
			}

			log.Println(jsonData)

			err = client.Set(userInfo.Email, string(jsonData), 0).Err()
			if err != nil {
				panic(err)
			}

			// Retrieving Info from Redis
			val, err := client.Get(userInfo.Email).Result()
			if err != nil {
				panic(err)
			}

			var retrievedInfo Info
			err = json.Unmarshal([]byte(val), &retrievedInfo)
			if err != nil {
				panic(err)
			}

			c.String(200, fmt.Sprintf("Token exchanged successfully. User: %+v", retrievedInfo))

		case err := <-errCh:
			c.String(500, fmt.Sprintf("Failed: %v", err))
		}
	})

	// 
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
