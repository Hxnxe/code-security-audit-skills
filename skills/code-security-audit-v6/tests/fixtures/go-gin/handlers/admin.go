package handlers

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func ListUsers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"users": []string{}})
}

func DeleteUser(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{"deleted": true, "id": id})
}
