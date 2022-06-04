package middleware

import (
	"fmt"
	"net/http"

	"github.com/aveplen-bach/resource-service/internal/ginutil"
	"github.com/aveplen-bach/resource-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func IncrementalToken(ts *service.TokenService) gin.HandlerFunc {
	logrus.Info("incremental token middleware registered")

	return func(c *gin.Context) {
		logrus.Info("incremental token middleware triggered")

		token, err := ginutil.ExtractToken(c)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		nextch := make(chan string)
		defer close(nextch)

		errch := make(chan error)
		defer close(errch)

		go func() {
			next, err := ts.NextToken(token)
			if err != nil {
				errch <- err
				return
			}
			nextch <- next
		}()

		select {
		case err := <-errch:
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		case next := <-nextch:
			c.Header("Authorizatoin", fmt.Sprintf("Bearer %s", next))
		}

		c.Next()
	}
}
