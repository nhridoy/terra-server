package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

type CreateTeamRequest struct {
	Name string `json:"name" binding:"required"`
}

type AddTeamMemberRequest struct {
	UserID string `json:"userId" binding:"required"`
	Role   string `json:"role"`
}

func ListTeams(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var teams []db.Team
	if result := db.GetDB().Where("owner_id = ?", userID).Find(&teams); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch teams"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"teams": teams})
}

func CreateTeam(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req CreateTeamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	team := db.Team{
		Name:    req.Name,
		OwnerID: userID,
	}

	if result := db.GetDB().Create(&team); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create team"})
		return
	}

	// Add owner as team member
	member := db.TeamMember{
		TeamID: team.ID,
		UserID: userID,
		Role:   "owner",
	}
	db.GetDB().Create(&member)

	c.JSON(http.StatusCreated, gin.H{"team": team})
}

func AddTeamMember(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	teamID := c.Param("id")

	// Verify user is team owner
	var team db.Team
	if result := db.GetDB().Where("id = ? AND owner_id = ?", teamID, userID).First(&team); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "team not found or unauthorized"})
		return
	}

	var req AddTeamMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if user exists
	var user db.User
	if result := db.GetDB().Where("id = ?", req.UserID).First(&user); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Check if already a member
	var existingMember db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, req.UserID).First(&existingMember); result.Error == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "user is already a team member"})
		return
	}

	role := req.Role
	if role == "" {
		role = "member"
	}

	member := db.TeamMember{
		TeamID:    teamID,
		UserID:    req.UserID,
		Role:      role,
		PublicKey: user.PublicKey,
	}

	if result := db.GetDB().Create(&member); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add team member"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"member": member})
}
