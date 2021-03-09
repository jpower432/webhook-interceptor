package main

import (
	"encoding/json"
	"fmt"
	"github.com/jpower432/webhook-interceptor/pkg/hmac"
	"io/ioutil"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

const sha = "sha256"

func main() {
	setupServer().Run()
}

// IsJSON is a function that check for valid JSON input
func IsJSON(str []byte) bool {
	var js json.RawMessage
	return json.Unmarshal(str, &js) == nil
}

// setupServer is a function that sets up a webserver and check the signature
func setupServer() *gin.Engine {
	r := gin.Default()

	r.Use(gin.Logger())

	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {

		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))

	r.POST("/test", func(c *gin.Context) {
		body, _ := ioutil.ReadAll(c.Request.Body)
		signature := c.GetHeader("X-Hub-Signature")
		secret := os.Getenv("WEBHOOK_SECRET")
		valid := hmac.Verify(body, signature, secret, sha)
		if valid == nil {
			if IsJSON(body) {
				c.String(200, string(body))
			} else {
				c.JSON(200, string(body))
			}
		} else {
			c.Error(valid)
			c.String(400, "Invalid request")
		}

	})

	r.GET("/health", func(c *gin.Context) {
		c.String(200, "All good")
	})

	return r
}
