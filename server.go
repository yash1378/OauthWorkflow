package main

import (
	"os"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go" // Import the jwt-go package
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"log"
	"net/http"
	"github.com/gin-contrib/cors"
	"time" // Import the time package
)

type UserInfo struct {
	Sub      string `json:"sub"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Picture  string `json:"picture"`
	Provider string `json:"iss"`
}
type Info struct {
	Email 	   string     `json:"Email"`
	Name       string     `json:"Name"`
	Coaching   string     `json:"Coaching"`
	Class      string     `json:"Class"`
	TestScores []TestInfo `json:"testScores"`
}

type TestInfo struct {
	Date       string `json:"date"`
	Type       string `json:"type"`
	TotalMarks int    `json:"totalMarks"`
	Maths      SubjectInfo `json:"maths"`
	Physics    SubjectInfo `json:"physics"`
	Chemistry  SubjectInfo `json:"chemistry"`
}

type SubjectInfo struct {
	MarksScored int `json:"marksScored"`
	SillyError  int `json:"sillyError"`
	Revision    int `json:"revision"`
	Toughness   int `json:"toughness"`
	Theory      int `json:"theory"`
}

type RequestData struct {
	Date    string `json:"date"`
	CorrectM int    `json:"correctm"`
	SillyM   int    `json:"sillym"`
	SlightM  int    `json:"slightm"`
	ToughM   int    `json:"toughm"`
	TheoryM  int    `json:"theorym"`
	CorrectP int    `json:"correctp"`
	SillyP   int    `json:"sillyp"`
	SlightP  int    `json:"slightp"`
	ToughP   int    `json:"toughp"`
	TheoryP  int    `json:"theoryp"`
	CorrectC int    `json:"correctc"`
	SillyC   int    `json:"sillyc"`
	SlightC  int    `json:"slightc"`
	ToughC   int    `json:"toughc"`
	TheoryC  int    `json:"theoryc"`
}

type advData struct {
	Date       string `json:"date"`
	Type       string `json:"type"`
	TotalMarks int    `json:"totalMarks"`
	Correct int    `json:"correct"`
	Silly   int    `json:"silly"`
	Slight  int    `json:"slight"`
	Tough   int    `json:"tough"`
	Theory  int    `json:"theory"`
}
type reqData struct {
	Date       string `json:"date"`
	Correct int    `json:"correct"`
	Silly   int    `json:"silly"`
	Slight  int    `json:"slight"`
	Tough   int    `json:"tough"`
	Theory  int    `json:"theory"`
}

type submit struct {
	Name            string `json:"name"`
	Dropdown1Value  string `json:"dropdown1Value"`
	Dropdown2Value  string `json:"dropdown2Value"`
}


// Claims represents the custom claims you want to include in the JWT
type Claims struct {
	Email  string `json:"email"`
	jwt.StandardClaims
}

func generateJWT(email string) (string, error) {
	// Your secret key for signing the token
	secretKey := []byte(os.Getenv("SECRET_KEY"))

	// Create a new JWT token with custom claims
	claims := &Claims{
		Email:  email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(), // Token expiration time (1 hour in this example)
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with your secret key
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// JWTMiddleware is a middleware function to check the JWT in the Authorization header
func JWTMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Parse the JWT from the Authorization header
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
            return
        }

        // Extract the JWT token from the Authorization header
        tokenString := authHeader[len("Bearer "):]

        // Parse and verify the JWT token
        claims := &Claims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return []byte(os.Getenv("SECRET_KEY")), nil // Replace with your actual secret key
        })

        if err != nil {
            if err == jwt.ErrSignatureInvalid {
                c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid JWT signature"})
                return
            }
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to parse JWT: %v", err)})
            return
        }

        // Check if the token is valid
        if !token.Valid {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid JWT"})
            return
        }

        // Set the email in the context for further use
        c.Set("email", claims.Email)

        // Continue with the next middleware or the actual handler
        c.Next()
    }
}




func main() {
	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURL := "http://localhost:3001/api/auth/google/callback"

	client := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_URL"),
		Password: os.Getenv("REDIS_PASSWORD"), // no password set
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
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	config.AllowHeaders = []string{"Authorization","Content-Type"} // Add this line to allow the 'Authorization' header
	router.Use(cors.New(config))
	
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
			// Check if the email is already present in the database
			emailExists, err := client.Exists(userInfo.Email).Result()
			if err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to check email existence: %v", err))
				return
			}

			var pre = false
	
			if emailExists == 0 {
				// Email does not exist, create a new record
				err := client.Set(userInfo.Email, "", 0).Err()
				pre = true
				if err != nil {
					c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to create new record: %v", err))
					return
				}
			// Storing Info in Redis
			log.Println(userInfo)
			var info Info
			info.Email = userInfo.Email
			info.Name = userInfo.Name
			jsonData, err := json.Marshal(info)
			if err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to marshal data: %v", err))
				return
			}
	
			log.Println(jsonData)
	
			// Set the user info data in Redis
			err = client.Set(userInfo.Email, string(jsonData), 0).Err()
			if err != nil {
				c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to set data in Redis: %v", err))
				return
			}
			}
	


			token,err:= generateJWT(userInfo.Email)
	
			// Redirect to the frontend or respond as needed
			// c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("http://localhost:3000?jwt=%s&new=%v", token,pre))
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("https://mainsite-lyart.vercel.app/?jwt=%s&new=%v", token,pre))

	
		case err := <-errCh:
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed: %v", err))
		}
	})


	
	// Your API endpoint
	router.POST("/mainsdata", JWTMiddleware(), func(c *gin.Context) {
		// Get the email from the context
		email, ok := c.Get("email")
		if !ok {
			c.String(http.StatusInternalServerError, "Failed to get email from context")
			return
		}

		// Now 'email' contains the email from the JWT claims
		log.Printf("Email from JWT: %s\n", email)

		// Parse the request body
		body, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("Failed to read request body: %v", err))
			return
		}

		// Unmarshal the JSON data into a struct
		var requestData RequestData
		if err := json.Unmarshal(body, &requestData); err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("Failed to unmarshal request body: %v", err))
			return
		}

		// Create SubjectInfo and TestInfo objects
		maths := SubjectInfo{
			MarksScored: requestData.CorrectM,
			SillyError:  requestData.SillyM,
			Revision:    requestData.SlightM,
			Toughness:   requestData.ToughM,
			Theory:      requestData.TheoryM,
		}

		physics := SubjectInfo{
			MarksScored: requestData.CorrectP,
			SillyError:  requestData.SillyP,
			Revision:    requestData.SlightP,
			Toughness:   requestData.ToughP,
			Theory:      requestData.TheoryP,
		}

		chem := SubjectInfo{
			MarksScored: requestData.CorrectC,
			SillyError:  requestData.SillyC,
			Revision:    requestData.SlightC,
			Toughness:   requestData.ToughC,
			Theory:      requestData.TheoryC,
		}

		test := TestInfo{
			Date:       requestData.Date,
			Type:       "mains",
			TotalMarks: 300,
			Maths:      maths,
			Physics:    physics,
			Chemistry:  chem,
		}

		// Retrieve the existing data from Redis
		existingData, err := client.Get(email.(string)).Result()
		if err == redis.Nil {
			// If the key doesn't exist, create a new Info struct
			existingData = `{"Email": "` + email.(string) + `", "testScores": []}`
		} else if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve data from Redis: %v", err))
			return
		}

		// Unmarshal the existing data
		var info Info
		err = json.Unmarshal([]byte(existingData), &info)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to unmarshal existing data: %v", err))
			return
		}

		// Append the new test score to the Tests array
		info.TestScores = append(info.TestScores, test)

		// Marshal the updated data
		updatedData, err := json.Marshal(info)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to marshal updated data: %v", err))
			return
		}

		// Save the updated data to Redis
		err = client.Set(email.(string), updatedData, 0).Err()
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to save data to Redis: %v", err))
			return
		}

		// Print the request body and email
		log.Printf("Received POST request body: %s\n", body)

		// Return status OK
		c.JSON(http.StatusOK, gin.H{"status": "OK"})
	})

	router.GET("/mainsdata", JWTMiddleware(), func(c *gin.Context) {
		// Get the email from the context
		email, ok := c.Get("email")
		if !ok {
			c.String(http.StatusInternalServerError, "Failed to get email from context")
			return
		}

		// Now 'email' contains the email from the JWT claims
		log.Printf("Email from JWT: %s\n", email)

		// Retrieve the existing data from Redis
		existingData, err := client.Get(email.(string)).Result()
		if err == redis.Nil {
			// If the key doesn't exist, create a new Info struct
			existingData = `{"Email": "` + email.(string) + `", "testScores": []}`
		} else if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve data from Redis: %v", err))
			return
		}

		// Unmarshal the existing data
		var info Info
		err = json.Unmarshal([]byte(existingData), &info)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to unmarshal existing data: %v", err))
			return
		}

		// Return the data
		c.JSON(http.StatusOK, info)
	})
	

	router.POST("/api/submit",JWTMiddleware(),func(c *gin.Context){
		email,ok:=c.Get("email")
		if !ok {
			c.String(http.StatusInternalServerError, "Failed to get email from context")
			return
		}
		// Now 'email' contains the email from the JWT claims
		log.Printf("Email from JWT: %s\n", email)

		// Parse the request body
		body, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("Failed to read request body: %v", err))
			return
		}

		// Unmarshal the JSON data into a struct
		var submitdata submit
		if err := json.Unmarshal(body, &submitdata); err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("Failed to unmarshal request body: %v", err))
			return
		}

		// Retrieve the existing data from Redis
		existingData, err := client.Get(email.(string)).Result()
		if err == redis.Nil {
			// If the key doesn't exist, create a new Info struct
			existingData = `{"Email": "` + email.(string) + `", "testScores": []}`
		} else if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve data from Redis: %v", err))
			return
		}

		// Unmarshal the existing data
		var info Info
		err = json.Unmarshal([]byte(existingData), &info)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to unmarshal existing data: %v", err))
			return
		}
		
		info.Name = submitdata.Name
		info.Class = submitdata.Dropdown1Value
		info.Coaching = submitdata.Dropdown2Value

		// Marshal the updated data
		updatedData, err := json.Marshal(info)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to marshal updated data: %v", err))
			return
		}

		// Save the updated data to Redis
		err = client.Set(email.(string), updatedData, 0).Err()
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to save data to Redis: %v", err))
			return
		}
	
		c.JSON(http.StatusOK, gin.H{"message": "User data saved successfully"})
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
