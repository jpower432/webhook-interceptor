package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"plugin"
	"time"
	"webhook-interceptor/pkg/hmac"

	"github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
)


type Interceptor interface {
	Intercept(*gin.Context, chan string)
}

func main() {
	var mod string
	var interceptor Interceptor
	var ok bool
	// argument is path to
	// custom interceptor module
	if len(os.Args) == 2 {
		mod = os.Args[1]

		// load module
		// 1. open the so file to load the symbols
		plug, err := plugin.Open(mod)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// look up a symbol (an exported function or variable)
		symInterceptor, err := plug.Lookup("Interceptor")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Assert that loaded symbol is of a desired type
		interceptor, ok = symInterceptor.(Interceptor)
		if !ok {
			fmt.Println("unexpected type from module symbol")
			os.Exit(1)
		}
	} else {
		// If no plugin is provided, use basic HMAC validation
		interceptor = hmac.Interceptor
	}

	setupServer(interceptor).Run()
}

// isJSON is a function that check for valid JSON input
func isJSON(str []byte) bool {
	var js json.RawMessage
	return json.Unmarshal(str, &js) == nil
}

// setupServer is a function that sets up a webserver and check the signature
func setupServer(interceptor Interceptor) *gin.Engine {
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

	r.POST("/intercept", func(c *gin.Context) {

		cCp := c.Copy()
		results := make(chan string)

		go interceptor.Intercept(cCp, results)

		for {
			select {
			case result := <-results:
				if isJSON([]byte(result)) {
					c.String(http.StatusOK, result)
				} else {
					c.JSON(http.StatusOK, result)
				}
			}
		}
	})

	r.GET("/health", func(c *gin.Context) {
		c.String(200, "All good")
	})

	return r
}
