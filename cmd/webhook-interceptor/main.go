package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/jpower432/webhook-interceptor/pkg/hmac"
	"github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
)

const sha = "sha256"

func main() {
	setupServer().Run()
}

// isJSON is a function that check for valid JSON input
func isJSON(str []byte) bool {
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

	header := os.Getenv("HEADER")
	logrus.Infof("Using header %s", header)

	r.POST("/test", func(c *gin.Context) {

		cCp := c.Copy()

		results := make(chan string)

		body, _ := ioutil.ReadAll(c.Request.Body)

		go func() {

			signature := cCp.GetHeader(header)
			secret := os.Getenv("WEBHOOK_SECRET")

			valid := hmac.Verify(body, signature, secret, sha)

			if valid == nil {
				results <- string(body)
			} else {
				results <- fmt.Sprintf("error: %v", valid)
				logrus.Error(valid)
			}

		}()

		if isJSON(body) {
			c.String(http.StatusOK, <-results)
		} else {
			c.JSON(http.StatusOK, <-results)
		}

	})

	r.GET("/health", func(c *gin.Context) {
		c.String(200, "All good")
	})

	return r
}
