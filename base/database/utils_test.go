package database

import (
	"app/base/utils"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	// counts of systems from system_inventory (+ system_patch join in Systems())
	nGroup1    int64 = 7
	nGroup2    int64 = 2
	nUngrouped int64 = 9
	nAll       int64 = 18
)

var testCases = []map[int64][]string{
	{nGroup1: {"inventory-group-1"}},
	{nGroup2: {"inventory-group-2"}},
	{nGroup1 + nGroup2: {"inventory-group-1", "inventory-group-2"}},
	{nGroup1 + nUngrouped: {"inventory-group-1", "root-workspace"}},
	{nUngrouped: {"non-existing-group", "root-workspace"}},
	{0: {"non-existing-group"}},
	{nUngrouped: {"root-workspace"}},
	{nAll: {"inventory-group-1", "inventory-group-2", "root-workspace"}},
}

func TestApplyInventoryWorkspaceFilter(t *testing.T) {
	utils.SkipWithoutDB(t)
	Configure()

	for _, tc := range testCases {
		for expectedCount, workspaceIDs := range tc {
			var count int64
			ApplyInventoryWorkspaceFilter(DB.Table("system_inventory si").
				Joins("JOIN system_patch spatch ON si.id = spatch.system_id AND si.rh_account_id = spatch.rh_account_id"),
				workspaceIDs).Count(&count)
			assert.Equal(t, expectedCount, count)
		}
	}
}
