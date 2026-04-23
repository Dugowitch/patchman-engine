package controllers

import (
	"app/base/database"
	"app/base/utils"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestGroupNameFilter(t *testing.T) {
	utils.SkipWithoutDB(t)
	database.Configure()

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request, _ = http.NewRequest("GET", "/?filter[group_name]=group2", nil)

	filters, err := ParseAllFilters(c, ListOpts{})
	assert.Nil(t, err)

	var systems2 []SystemsID
	workspaceIDs := []string{"inventory-group-1", "inventory-group-2"}
	ty := database.Systems(database.DB, 1, workspaceIDs)
	ty, _ = ApplyInventoryFilter(filters, ty, "si.inventory_id")
	ty.Scan(&systems2)

	assert.Equal(t, 2, len(systems2))
	assert.Equal(t, "00000000-0000-0000-0000-000000000007", systems2[0].ID)
	assert.Equal(t, "00000000-0000-0000-0000-000000000008", systems2[1].ID)
}

func TestGroupNameFilter2(t *testing.T) {
	utils.SkipWithoutDB(t)
	database.Configure()

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request, _ = http.NewRequest("GET", "/?filter[group_name]=group1,group2", nil)

	filters, err := ParseAllFilters(c, ListOpts{})
	assert.Nil(t, err)

	var systems2 []SystemsID
	workspaceIDs := []string{"inventory-group-1", "inventory-group-2"}
	ty := database.Systems(database.DB, 1, workspaceIDs)
	ty, _ = ApplyInventoryFilter(filters, ty, "si.inventory_id")
	ty.Scan(&systems2)

	assert.Equal(t, 9, len(systems2))
}
