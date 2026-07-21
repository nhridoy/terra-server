package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
	"gorm.io/gorm"
)

type CreateTeamRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

type AddMemberRequest struct {
	Email string `json:"email" binding:"required,email"`
	Role  string `json:"role" binding:"required,oneof=owner admin member"`
}

func ListTeams(c *gin.Context) {
	userID := auth.GetUserID(c)

	var memberships []db.TeamMember
	db.GetDB().Where("user_id = ?", userID).Find(&memberships)

	teamIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		teamIDs = append(teamIDs, m.TeamID)
	}

	if len(teamIDs) == 0 {
		c.JSON(http.StatusOK, []db.Team{})
		return
	}

	var teams []db.Team
	db.GetDB().Where("id IN ?", teamIDs).Find(&teams)
	c.JSON(http.StatusOK, teams)
}

func CreateTeam(c *gin.Context) {
	userID := auth.GetUserID(c)

	var req CreateTeamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user db.User
	if result := db.GetDB().Where("id = ?", userID).First(&user); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	team := db.Team{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		OwnerID:     userID,
	}

	if err := db.GetDB().Create(&team).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create team"})
		return
	}

	// Add owner as first member
	member := db.TeamMember{
		ID:       uuid.New().String(),
		TeamID:   team.ID,
		UserID:   userID,
		Username: user.Username,
		Email:    user.Email,
		Role:     "owner",
		JoinedAt: time.Now(),
	}
	db.GetDB().Create(&member)

	c.JSON(http.StatusCreated, team)
}

func GetTeam(c *gin.Context) {
	userID := auth.GetUserID(c)
	teamID := c.Param("id")

	// Verify membership
	var membership db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, userID).First(&membership); result.Error != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "not a team member"})
		return
	}

	var team db.Team
	if result := db.GetDB().Where("id = ?", teamID).First(&team); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "team not found"})
		return
	}

	var members []db.TeamMember
	db.GetDB().Where("team_id = ?", teamID).Find(&members)

	c.JSON(http.StatusOK, gin.H{
		"team":    team,
		"members": members,
	})
}

func UpdateTeam(c *gin.Context) {
	userID := auth.GetUserID(c)
	teamID := c.Param("id")

	// Only owner or admin can update
	var membership db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, userID).First(&membership); result.Error != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "not a team member"})
		return
	}
	if membership.Role != "owner" && membership.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	var team db.Team
	if result := db.GetDB().Where("id = ?", teamID).First(&team); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "team not found"})
		return
	}

	var req CreateTeamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	team.Name = req.Name
	team.Description = req.Description

	if err := db.GetDB().Save(&team).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update team"})
		return
	}

	c.JSON(http.StatusOK, team)
}

func DeleteTeam(c *gin.Context) {
	userID := auth.GetUserID(c)
	teamID := c.Param("id")

	// Only owner can delete
	var membership db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, userID).First(&membership); result.Error != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "not a team member"})
		return
	}
	if membership.Role != "owner" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only the owner can delete the team"})
		return
	}

	if err := db.InTransaction(func(tx *gorm.DB) error {
		tx.Where("team_id = ?", teamID).Delete(&db.TeamMember{})
		tx.Where("team_id = ?", teamID).Delete(&db.SharedVault{})
		return tx.Delete(&db.Team{}, teamID).Error
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete team"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "team deleted"})
}

func AddMember(c *gin.Context) {
	userID := auth.GetUserID(c)
	teamID := c.Param("id")

	// Check membership and role
	var membership db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, userID).First(&membership); result.Error != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "not a team member"})
		return
	}
	if membership.Role != "owner" && membership.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	var req AddMemberRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find user by email
	var targetUser db.User
	if result := db.GetDB().Where("email = ?", req.Email).First(&targetUser); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found with that email"})
		return
	}

	// Check if already a member
	var existing db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, targetUser.ID).First(&existing); result.Error == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "user is already a team member"})
		return
	}

	newMember := db.TeamMember{
		ID:       uuid.New().String(),
		TeamID:   teamID,
		UserID:   targetUser.ID,
		Username: targetUser.Username,
		Email:    targetUser.Email,
		Role:     req.Role,
		JoinedAt: time.Now(),
	}

	if err := db.GetDB().Create(&newMember).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add member"})
		return
	}

	c.JSON(http.StatusCreated, newMember)
}

func RemoveMember(c *gin.Context) {
	userID := auth.GetUserID(c)
	teamID := c.Param("id")
	memberID := c.Param("memberId")

	// Check membership and role
	var membership db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, userID).First(&membership); result.Error != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "not a team member"})
		return
	}

	// Users can remove themselves (leave), or admins/owner can remove others
	if userID != memberID && membership.Role != "owner" && membership.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	// Cannot remove the owner
	var targetMember db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, memberID).First(&targetMember); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "member not found"})
		return
	}
	if targetMember.Role == "owner" && userID != memberID {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot remove the owner"})
		return
	}

	db.GetDB().Delete(&targetMember)
	c.JSON(http.StatusOK, gin.H{"message": "member removed"})
}

func UpdateMemberRole(c *gin.Context) {
	userID := auth.GetUserID(c)
	teamID := c.Param("id")
	memberID := c.Param("memberId")

	// Only owner can change roles
	var membership db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, userID).First(&membership); result.Error != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "not a team member"})
		return
	}
	if membership.Role != "owner" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only the owner can change roles"})
		return
	}

	var req struct {
		Role string `json:"role" binding:"required,oneof=owner admin member"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var targetMember db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, memberID).First(&targetMember); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "member not found"})
		return
	}

	targetMember.Role = req.Role
	db.GetDB().Save(&targetMember)

	c.JSON(http.StatusOK, targetMember)
}

// ---- Shared Vaults ----

type CreateSharedVaultRequest struct {
	VaultID string `json:"vaultId" binding:"required"`
	Name    string `json:"name"`
}

func ListSharedVaults(c *gin.Context) {
	userID := auth.GetUserID(c)
	teamID := c.Param("id")

	// Verify membership
	var membership db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, userID).First(&membership); result.Error != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "not a team member"})
		return
	}

	var sharedVaults []db.SharedVault
	db.GetDB().Where("team_id = ?", teamID).Find(&sharedVaults)
	c.JSON(http.StatusOK, sharedVaults)
}

func CreateSharedVault(c *gin.Context) {
	userID := auth.GetUserID(c)
	teamID := c.Param("id")

	// Verify membership
	var membership db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, userID).First(&membership); result.Error != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "not a team member"})
		return
	}
	if membership.Role != "owner" && membership.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	var req CreateSharedVaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify the vault exists and belongs to the user
	var vault db.Vault
	if result := db.GetDB().Where("id = ? AND user_id = ?", req.VaultID, userID).First(&vault); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vault not found"})
		return
	}

	sharedVault := db.SharedVault{
		ID:      uuid.New().String(),
		TeamID:  teamID,
		VaultID: req.VaultID,
		Name:    req.Name,
	}

	if req.Name == "" {
		sharedVault.Name = vault.Name
	}

	if err := db.GetDB().Create(&sharedVault).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create shared vault"})
		return
	}

	c.JSON(http.StatusCreated, sharedVault)
}

func DeleteSharedVault(c *gin.Context) {
	userID := auth.GetUserID(c)
	teamID := c.Param("id")
	vaultID := c.Param("vaultId")

	// Verify membership
	var membership db.TeamMember
	if result := db.GetDB().Where("team_id = ? AND user_id = ?", teamID, userID).First(&membership); result.Error != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "not a team member"})
		return
	}
	if membership.Role != "owner" && membership.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	result := db.GetDB().Where("team_id = ? AND id = ?", teamID, vaultID).Delete(&db.SharedVault{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "shared vault not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "shared vault removed"})
}
