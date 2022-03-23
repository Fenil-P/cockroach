package security

import (
	"github.com/lib/pq/oid"
	"strconv"
)

// SQLUserInfo s
type SQLUserInfo struct {
	Username SQLUsername
	UserID   oid.Oid
}

// MakeSQLUserInfoFromPreNormalizedString takes a string containing a
// canonical username and user id and converts it to a SQLUsername. The caller
// of this promises that the username argument is pre-normalized. This conversion
// is cheap.
// Note: avoid using this function when processing strings
// in requests from external APIs.
func MakeSQLUserInfoFromPreNormalizedString(username string, ID string) SQLUserInfo {
	if string(ID[0]) == "'" {
		ID = ID[1:len(ID)]
	}
	if string(ID[len(ID)-1]) == "'" {
		ID = ID[:len(ID)-1]
	}
	i, err := strconv.Atoi(ID)
	if err != nil {
		panic(err)
	}
	return SQLUserInfo{Username: MakeSQLUsernameFromPreNormalizedString(username), UserID: oid.Oid(i)}
}

// RootUserInfo is the SQLUserInfo for RootUser.
func RootUserInfo() SQLUserInfo { return SQLUserInfo{RootUserName(), 1} }

// AdminRoleInfo is the SQLUserInfo for AdminRole.
func AdminRoleInfo() SQLUserInfo { return SQLUserInfo{AdminRoleName(), 2} }

// PublicRoleInfo is the SQLUserInfo for PublicRole.
func PublicRoleInfo() SQLUserInfo { return SQLUserInfo{PublicRoleName(), 3} }

// NodeUserInfo is the SQLUserInfo for NodeUser.
func NodeUserInfo() SQLUserInfo { return SQLUserInfo{NodeUserName(), 4} }

// TestUserInfo is the SQLUserInfo for testuser.
func TestUserInfo() SQLUserInfo { return SQLUserInfo{TestUserName(), 5} }
