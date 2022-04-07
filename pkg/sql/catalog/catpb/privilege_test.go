// Copyright 2015 The Cockroach Authors.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package catpb_test

import (
	"reflect"
	"testing"

	"github.com/cockroachdb/cockroach/pkg/keys"
	"github.com/cockroachdb/cockroach/pkg/security"
	"github.com/cockroachdb/cockroach/pkg/sql/catalog/bootstrap"
	"github.com/cockroachdb/cockroach/pkg/sql/catalog/catpb"
	"github.com/cockroachdb/cockroach/pkg/sql/privilege"
	"github.com/cockroachdb/cockroach/pkg/sql/sem/catid"
	"github.com/cockroachdb/cockroach/pkg/testutils"
	"github.com/cockroachdb/cockroach/pkg/util/leaktest"
)

func TestPrivilege(t *testing.T) {
	defer leaktest.AfterTest(t)()
	descriptor := catpb.NewBasePrivilegeDescriptor(security.AdminRoleInfo())

	testUser := security.TestUserInfo()
	barUser := security.MakeSQLUserInfoFromPreNormalizedString("bar", 52)

	testCases := []struct {
		grantee       security.SQLUserInfo // User to grant/revoke privileges on.
		grant, revoke privilege.List
		show          []catpb.UserPrivilege
		objectType    privilege.ObjectType
	}{
		{security.SQLUserInfo{}, nil, nil,
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{security.RootUserInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
			},
			privilege.Table,
		},
		{security.RootUserInfo(), privilege.List{privilege.ALL}, nil,
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{security.RootUserInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
			},
			privilege.Table,
		},
		{security.RootUserInfo(), privilege.List{privilege.INSERT, privilege.DROP}, nil,
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{security.RootUserInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
			},
			privilege.Table,
		},
		{testUser, privilege.List{privilege.INSERT, privilege.DROP}, nil,
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{security.RootUserInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{testUser, []privilege.Privilege{{Kind: privilege.DROP}, {Kind: privilege.INSERT}}},
			},
			privilege.Table,
		},
		{barUser, nil, privilege.List{privilege.INSERT, privilege.ALL},
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{security.RootUserInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{testUser, []privilege.Privilege{{Kind: privilege.DROP}, {Kind: privilege.INSERT}}},
			},
			privilege.Table,
		},
		{testUser, privilege.List{privilege.ALL}, nil,
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{security.RootUserInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{testUser, []privilege.Privilege{{Kind: privilege.ALL}}},
			},
			privilege.Table,
		},
		{testUser, nil, privilege.List{privilege.SELECT, privilege.INSERT},
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{security.RootUserInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{testUser, []privilege.Privilege{
					{Kind: privilege.CREATE},
					{Kind: privilege.DELETE},
					{Kind: privilege.DROP},
					{Kind: privilege.GRANT},
					{Kind: privilege.UPDATE},
					{Kind: privilege.ZONECONFIG},
				}},
			},
			privilege.Table,
		},
		{testUser, nil, privilege.List{privilege.ALL},
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{security.RootUserInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
			},
			privilege.Table,
		},
		// Validate checks that root still has ALL privileges, but we do not call it here.
		{security.RootUserInfo(), nil, privilege.List{privilege.ALL},
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
			},
			privilege.Table,
		},
		// Ensure revoking USAGE from a user with ALL privilege on a type
		// leaves the user with only GRANT privilege.
		{testUser, privilege.List{privilege.ALL}, privilege.List{privilege.USAGE},
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
				{testUser, []privilege.Privilege{{Kind: privilege.GRANT}}},
			},
			privilege.Type,
		},
		// Ensure revoking USAGE, GRANT from a user with ALL privilege on a type
		// leaves the user with no privileges.
		{testUser,
			privilege.List{privilege.ALL}, privilege.List{privilege.USAGE, privilege.GRANT},
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
			},
			privilege.Type,
		},
		// Ensure revoking CREATE, DROP, GRANT, SELECT, INSERT, DELETE, UPDATE, ZONECONFIG
		// from a user with ALL privilege on a table leaves the user with no privileges.
		{testUser,
			privilege.List{privilege.ALL},
			privilege.List{privilege.CREATE, privilege.DROP, privilege.GRANT, privilege.SELECT, privilege.INSERT,
				privilege.DELETE, privilege.UPDATE, privilege.ZONECONFIG},
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
			},
			privilege.Table,
		},
		// Ensure revoking CONNECT, CREATE, DROP, GRANT, SELECT, INSERT, DELETE, UPDATE, ZONECONFIG
		// from a user with ALL privilege on a database leaves the user with no privileges.
		{testUser,
			privilege.List{privilege.ALL},
			privilege.List{privilege.CONNECT, privilege.CREATE, privilege.DROP, privilege.GRANT, privilege.SELECT,
				privilege.INSERT, privilege.DELETE, privilege.UPDATE, privilege.ZONECONFIG},
			[]catpb.UserPrivilege{
				{security.AdminRoleInfo(), []privilege.Privilege{{Kind: privilege.ALL, GrantOption: true}}},
			},
			privilege.Database,
		},
	}

	for tcNum, tc := range testCases {
		if !tc.grantee.Username.Undefined() {
			if tc.grant != nil {
				descriptor.Grant(tc.grantee, tc.grant, false)
			}
			if tc.revoke != nil {
				descriptor.Revoke(tc.grantee, tc.revoke, tc.objectType, false)
			}
		}
		show := descriptor.Show(tc.objectType)
		if len(show) != len(tc.show) {
			t.Fatalf("#%d: show output for descriptor %+v differs, got: %+v, expected %+v",
				tcNum, descriptor, show, tc.show)
		}
		for i := 0; i < len(show); i++ {
			if !reflect.DeepEqual(show[i], tc.show[i]) {
				t.Fatalf("#%d: show output for descriptor %+v differs, got: %+v, expected %+v",
					tcNum, descriptor, show, tc.show)
			}
		}
	}
}

func TestCheckPrivilege(t *testing.T) {
	defer leaktest.AfterTest(t)()

	testUser := security.TestUserInfo()
	barUser := security.MakeSQLUserInfoFromPreNormalizedString("bar", 52)

	testCases := []struct {
		pd   *catpb.PrivilegeDescriptor
		user security.SQLUserInfo
		priv privilege.Kind
		exp  bool
	}{
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.CREATE, true},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE}, privilege.List{}, security.AdminRoleInfo()),
			barUser, privilege.CREATE, false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE}, privilege.List{}, security.AdminRoleInfo()),
			barUser, privilege.DROP, false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.DROP, false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.ALL}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.CREATE, true},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.ALL, false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.ALL}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.ALL, true},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.ALL, false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.CREATE, false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE, privilege.DROP}, privilege.List{},
			security.AdminRoleInfo()),
			testUser, privilege.UPDATE, false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE, privilege.DROP}, privilege.List{},
			security.AdminRoleInfo()),
			testUser, privilege.DROP, true},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE, privilege.ALL}, privilege.List{},
			security.AdminRoleInfo()),
			testUser, privilege.DROP, true},
	}

	for tcNum, tc := range testCases {
		if found := tc.pd.CheckPrivilege(tc.user, tc.priv); found != tc.exp {
			t.Errorf("#%d: CheckPrivilege(%s, %v) for descriptor %+v = %t, expected %t",
				tcNum, tc.user.Username, tc.priv, tc.pd, found, tc.exp)
		}
	}
}

func TestAnyPrivilege(t *testing.T) {
	defer leaktest.AfterTest(t)()

	testUser := security.TestUserInfo()
	barUser := security.MakeSQLUserInfoFromPreNormalizedString("bar", 52)

	testCases := []struct {
		pd   *catpb.PrivilegeDescriptor
		user security.SQLUserInfo
		exp  bool
	}{
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE}, privilege.List{}, security.AdminRoleInfo()),
			testUser, true},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE}, privilege.List{}, security.AdminRoleInfo()),
			barUser, false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.ALL}, privilege.List{}, security.AdminRoleInfo()),
			testUser, true},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{}, privilege.List{}, security.AdminRoleInfo()),
			testUser, false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE, privilege.DROP}, privilege.List{},
			security.AdminRoleInfo()),
			testUser, true},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE, privilege.DROP}, privilege.List{},
			security.AdminRoleInfo()),
			barUser, false},
	}

	for tcNum, tc := range testCases {
		if found := tc.pd.AnyPrivilege(tc.user); found != tc.exp {
			t.Errorf("#%d: AnyPrivilege(%s) for descriptor %+v = %t, expected %t",
				tcNum, tc.user.Username, tc.pd, found, tc.exp)
		}
	}
}

// TestPrivilegeValidate exercises validation for non-system descriptors.
func TestPrivilegeValidate(t *testing.T) {
	defer leaktest.AfterTest(t)()

	testUser := security.TestUserInfo()

	descriptor := catpb.NewBasePrivilegeDescriptor(security.AdminRoleInfo())
	validate := func() error {
		id := catid.DescID(bootstrap.TestingMinUserDescID())
		return descriptor.Validate(id, privilege.Table, "whatever", catpb.DefaultSuperuserPrivileges)
	}

	if err := validate(); err != nil {
		t.Fatal(err)
	}
	descriptor.Grant(testUser, privilege.List{privilege.ALL}, false)
	if err := validate(); err != nil {
		t.Fatal(err)
	}
	descriptor.Grant(security.RootUserInfo(), privilege.List{privilege.SELECT}, false)
	if err := validate(); err != nil {
		t.Fatal(err)
	}
	descriptor.Revoke(security.RootUserInfo(), privilege.List{privilege.SELECT}, privilege.Table, false)
	if err := validate(); err == nil {
		t.Fatal("unexpected success")
	}
	// TODO(marc): validate fails here because we do not aggregate
	// privileges into ALL when all are set.
	descriptor.Grant(security.RootUserInfo(), privilege.List{privilege.SELECT}, false)
	if err := validate(); err == nil {
		t.Fatal("unexpected success")
	}
	descriptor.Revoke(security.RootUserInfo(), privilege.List{privilege.ALL}, privilege.Table, false)
	if err := validate(); err == nil {
		t.Fatal("unexpected success")
	}
}

func TestValidPrivilegesForObjects(t *testing.T) {
	defer leaktest.AfterTest(t)()
	id := catid.DescID(bootstrap.TestingMinUserDescID())

	testUser := security.TestUserInfo()

	testCases := []struct {
		objectType      privilege.ObjectType
		validPrivileges privilege.List
	}{
		{privilege.Table, privilege.TablePrivileges},
		{privilege.Database, privilege.DBPrivileges},
		{privilege.Schema, privilege.SchemaPrivileges},
		{privilege.Type, privilege.TypePrivileges},
	}

	for _, tc := range testCases {
		for _, priv := range tc.validPrivileges {
			privDesc := catpb.NewBasePrivilegeDescriptor(security.AdminRoleInfo())
			privDesc.Grant(testUser, privilege.List{priv}, false)
			err := privDesc.Validate(id, tc.objectType, "whatever", catpb.DefaultSuperuserPrivileges)
			if err != nil {
				t.Fatal(err)
			}
		}

		// Derive invalidPrivileges from the validPrivileges.
		invalidPrivileges := privilege.List{}
		for _, priv := range privilege.AllPrivileges {
			if priv.Mask() & ^tc.validPrivileges.ToBitField() != 0 {
				invalidPrivileges = append(invalidPrivileges, priv)
			}
		}

		for _, priv := range invalidPrivileges {
			privDesc := catpb.NewBasePrivilegeDescriptor(security.AdminRoleInfo())
			privDesc.Grant(testUser, privilege.List{priv}, false)
			err := privDesc.Validate(id, tc.objectType, "whatever", catpb.DefaultSuperuserPrivileges)
			if err == nil {
				t.Fatalf("unexpected success, %s should not be a valid privilege for a %s",
					priv, tc.objectType)
			}
		}
	}
}

// TestSystemPrivilegeValidate exercises validation for system config
// descriptors. We use a dummy system table installed for testing
// purposes.
func TestSystemPrivilegeValidate(t *testing.T) {
	defer leaktest.AfterTest(t)()

	testUser := security.TestUserInfo()

	validate := func(descriptor *catpb.PrivilegeDescriptor) error {
		return descriptor.Validate(keys.SystemDatabaseID, privilege.Table, "whatever", privilege.ReadData)
	}

	rootWrongPrivilegesErr := "user root must have exactly GRANT, SELECT " +
		`privileges on (system )?table "whatever"`
	adminWrongPrivilegesErr := "user admin must have exactly GRANT, SELECT " +
		`privileges on (system )?table "whatever"`

	{
		// Valid: root user has one of the allowable privilege sets.
		descriptor := catpb.NewCustomSuperuserPrivilegeDescriptor(
			privilege.List{privilege.SELECT, privilege.GRANT},
			security.AdminRoleInfo(),
		)
		if err := validate(descriptor); err != nil {
			t.Fatal(err)
		}

		// Valid: foo has a subset of the allowed privileges.
		descriptor.Grant(testUser, privilege.List{privilege.SELECT}, false)
		if err := validate(descriptor); err != nil {
			t.Fatal(err)
		}

		// Valid: foo has exactly the allowed privileges.
		descriptor.Grant(testUser, privilege.List{privilege.GRANT}, false)
		if err := validate(descriptor); err != nil {
			t.Fatal(err)
		}
	}

	{
		// Valid: root has exactly the allowed privileges.
		descriptor := catpb.NewCustomSuperuserPrivilegeDescriptor(
			privilege.List{privilege.SELECT, privilege.GRANT},
			security.AdminRoleInfo(),
		)

		// Valid: foo has a subset of the allowed privileges.
		descriptor.Grant(testUser, privilege.List{privilege.GRANT}, false)
		if err := validate(descriptor); err != nil {
			t.Fatal(err)
		}

		// Valid: foo can have privileges revoked, including privileges it doesn't currently have.
		descriptor.Revoke(
			testUser, privilege.List{privilege.GRANT, privilege.UPDATE, privilege.ALL}, privilege.Table, false)
		if err := validate(descriptor); err != nil {
			t.Fatal(err)
		}

		// Invalid: root user has too many privileges.
		descriptor.Grant(security.RootUserInfo(), privilege.List{privilege.UPDATE}, false)
		if err := validate(descriptor); !testutils.IsError(err, rootWrongPrivilegesErr) {
			t.Fatalf("expected err=%s, got err=%v", rootWrongPrivilegesErr, err)
		}
	}

	{
		// Invalid: root has a non-allowable privilege set.
		descriptor := catpb.NewCustomSuperuserPrivilegeDescriptor(privilege.List{privilege.UPDATE},
			security.AdminRoleInfo())
		if err := validate(descriptor); !testutils.IsError(err, rootWrongPrivilegesErr) {
			t.Fatalf("expected err=%s, got err=%v", rootWrongPrivilegesErr, err)
		}

		// Invalid: root's invalid privileges are revoked and replaced with allowable privileges,
		// but admin is still wrong.
		descriptor.Revoke(security.RootUserInfo(), privilege.List{privilege.UPDATE}, privilege.Table, false)
		descriptor.Grant(security.RootUserInfo(), privilege.List{privilege.SELECT, privilege.GRANT}, false)
		if err := validate(descriptor); !testutils.IsError(err, adminWrongPrivilegesErr) {
			t.Fatalf("expected err=%s, got err=%v", adminWrongPrivilegesErr, err)
		}

		// Valid: admin's invalid privileges are revoked and replaced with allowable privileges.
		descriptor.Revoke(security.AdminRoleInfo(), privilege.List{privilege.UPDATE}, privilege.Table, false)
		descriptor.Grant(security.AdminRoleInfo(), privilege.List{privilege.SELECT, privilege.GRANT}, false)
		if err := validate(descriptor); err != nil {
			t.Fatal(err)
		}

		// Valid: foo has less privileges than root.
		descriptor.Grant(testUser, privilege.List{privilege.GRANT}, false)
		if err := validate(descriptor); err != nil {
			t.Fatal(err)
		}
	}
}

func TestValidateOwnership(t *testing.T) {
	defer leaktest.AfterTest(t)()

	// Use a non-system id.
	id := catid.DescID(bootstrap.TestingMinUserDescID())
	validate := func(privs catpb.PrivilegeDescriptor) error {
		return privs.Validate(id, privilege.Table, "whatever", catpb.DefaultSuperuserPrivileges)
	}

	// A privilege descriptor with a version before OwnerVersion can have
	// no owner.
	privs := catpb.PrivilegeDescriptor{
		Users: []catpb.UserPrivileges{
			{
				UserProto:  security.AdminRoleName().EncodeProto(),
				Privileges: catpb.DefaultSuperuserPrivileges.ToBitField(),
				UserId:     security.AdminRoleInfo().UserID,
			},
			{
				UserProto:  security.RootUserName().EncodeProto(),
				Privileges: catpb.DefaultSuperuserPrivileges.ToBitField(),
				UserId:     security.RootUserInfo().UserID,
			},
		}}
	err := validate(privs)
	if err != nil {
		t.Fatal(err)
	}

	// A privilege descriptor with version OwnerVersion and onwards should
	// have an owner.
	privs = catpb.PrivilegeDescriptor{
		Users: []catpb.UserPrivileges{
			{
				UserProto:  security.AdminRoleName().EncodeProto(),
				Privileges: catpb.DefaultSuperuserPrivileges.ToBitField(),
				UserId:     security.AdminRoleInfo().UserID,
			},
			{
				UserProto:  security.RootUserName().EncodeProto(),
				Privileges: catpb.DefaultSuperuserPrivileges.ToBitField(),
				UserId:     security.RootUserInfo().UserID,
			},
		},
		Version: catpb.OwnerVersion,
	}

	err = validate(privs)
	if err == nil {
		t.Fatal("unexpected success")
	}

	privs = catpb.PrivilegeDescriptor{
		OwnerProto: security.RootUserName().EncodeProto(),
		Users: []catpb.UserPrivileges{
			{
				UserProto:  security.AdminRoleName().EncodeProto(),
				Privileges: catpb.DefaultSuperuserPrivileges.ToBitField(),
				UserId:     security.AdminRoleInfo().UserID,
			},
			{
				UserProto:  security.RootUserName().EncodeProto(),
				Privileges: catpb.DefaultSuperuserPrivileges.ToBitField(),
				UserId:     security.RootUserInfo().UserID,
			},
		},
		Version: catpb.OwnerVersion,
	}

	err = validate(privs)
	if err != nil {
		t.Fatal(err)
	}
}

// TestGrantWithGrantOption tests whether granting with grant option changes the
// privilege bits and grant option bits as expected.
func TestGrantWithGrantOption(t *testing.T) {
	defer leaktest.AfterTest(t)()

	testUser := security.TestUserInfo()

	testCases := []struct {
		pd                  *catpb.PrivilegeDescriptor
		user                security.SQLUserInfo
		objectType          privilege.ObjectType
		grantPrivileges     privilege.List
		expectedPrivileges  privilege.List
		expectedGrantOption privilege.List
	}{
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			privilege.List{privilege.SELECT, privilege.INSERT},
			privilege.List{privilege.SELECT, privilege.INSERT},
			privilege.List{privilege.SELECT, privilege.INSERT}},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			privilege.List{privilege.SELECT, privilege.INSERT},
			privilege.List{privilege.CREATE, privilege.SELECT, privilege.INSERT},
			privilege.List{privilege.SELECT, privilege.INSERT}},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.ALL}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			privilege.List{privilege.SELECT, privilege.INSERT},
			privilege.List{privilege.ALL, privilege.SELECT, privilege.INSERT},
			privilege.List{privilege.SELECT, privilege.INSERT}},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.INSERT}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			privilege.List{privilege.ALL},
			privilege.List{privilege.ALL},
			privilege.List{privilege.ALL}},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.ALL}, privilege.List{privilege.ALL}, security.AdminRoleInfo()),
			testUser, privilege.Schema,
			privilege.List{privilege.ALL},
			privilege.List{privilege.ALL},
			privilege.List{privilege.ALL}},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE}, privilege.List{privilege.CREATE}, security.AdminRoleInfo()),
			testUser, privilege.Schema,
			privilege.List{privilege.ALL, privilege.CREATE},
			privilege.List{privilege.ALL},
			privilege.List{privilege.ALL}},
	}

	for tcNum, tc := range testCases {
		tc.pd.Grant(tc.user, tc.grantPrivileges, true)
		if tc.pd.Users[0].Privileges != tc.expectedPrivileges.ToBitField() {
			t.Errorf("#%d: Incorrect privileges, returned %v, expected %v",
				tcNum, privilege.ListFromBitField(tc.pd.Users[0].Privileges, tc.objectType), tc.expectedPrivileges)
		}
		if tc.pd.Users[0].WithGrantOption != tc.expectedGrantOption.ToBitField() {
			t.Errorf("#%d: Incorrect grant option, returned %v, expected %v",
				tcNum, privilege.ListFromBitField(tc.pd.Users[0].WithGrantOption, tc.objectType), tc.expectedGrantOption)
		}
	}
}

// TestRevokeWithGrantOption tests whether revoking grant option for changes the
// privilege bits and grant option bits as expected.
func TestRevokeWithGrantOption(t *testing.T) {
	defer leaktest.AfterTest(t)()

	testUser := security.TestUserInfo()

	testCases := []struct {
		pd                  *catpb.PrivilegeDescriptor
		user                security.SQLUserInfo
		objectType          privilege.ObjectType
		grantOptionFor      bool
		revokePrivileges    privilege.List
		expectedPrivileges  privilege.List
		expectedGrantOption privilege.List
		shouldBeEmpty       bool
	}{
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.ALL}, privilege.List{}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			true,
			privilege.List{privilege.ALL},
			privilege.List{privilege.ALL},
			privilege.List{},
			false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.ALL}, privilege.List{privilege.ALL}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			true,
			privilege.List{privilege.CREATE, privilege.GRANT},
			privilege.List{privilege.ALL},
			privilege.List{privilege.DROP, privilege.SELECT, privilege.INSERT, privilege.DELETE, privilege.UPDATE, privilege.ZONECONFIG},
			false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.ALL}, privilege.List{privilege.ALL}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			true,
			privilege.List{privilege.ALL},
			privilege.List{privilege.ALL},
			privilege.List{},
			false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.ALL}, privilege.List{privilege.ALL}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			true,
			privilege.List{privilege.ALL, privilege.CREATE, privilege.SELECT},
			privilege.List{privilege.ALL},
			privilege.List{},
			false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE, privilege.SELECT, privilege.INSERT}, privilege.List{privilege.SELECT}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			true,
			privilege.List{privilege.CREATE, privilege.DROP, privilege.SELECT},
			privilege.List{privilege.CREATE, privilege.SELECT, privilege.INSERT},
			privilege.List{},
			false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.CREATE, privilege.SELECT, privilege.INSERT}, privilege.List{privilege.CREATE, privilege.SELECT, privilege.INSERT}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			false,
			privilege.List{privilege.SELECT, privilege.INSERT},
			privilege.List{privilege.CREATE},
			privilege.List{privilege.CREATE},
			false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.ALL}, privilege.List{privilege.ALL}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			false,
			privilege.List{privilege.CREATE, privilege.GRANT},
			privilege.List{privilege.DROP, privilege.SELECT, privilege.INSERT, privilege.DELETE, privilege.UPDATE, privilege.ZONECONFIG},
			privilege.List{privilege.DROP, privilege.SELECT, privilege.INSERT, privilege.DELETE, privilege.UPDATE, privilege.ZONECONFIG},
			false},
		{catpb.NewPrivilegeDescriptor(testUser, privilege.List{privilege.SELECT, privilege.INSERT}, privilege.List{privilege.INSERT}, security.AdminRoleInfo()),
			testUser, privilege.Table,
			false,
			privilege.List{privilege.ALL},
			privilege.List{},
			privilege.List{},
			true},
	}

	for tcNum, tc := range testCases {
		tc.pd.Revoke(tc.user, tc.revokePrivileges, tc.objectType, tc.grantOptionFor)
		if tc.shouldBeEmpty {
			if len(tc.pd.Users) == 0 {
				continue
			}
			t.Errorf("#%d: Descriptor exists when it should be deleted",
				tcNum)
		}
		if tc.pd.Users[0].Privileges != tc.expectedPrivileges.ToBitField() {
			t.Errorf("#%d: Incorrect privileges, returned %v, expected %v",
				tcNum, privilege.ListFromBitField(tc.pd.Users[0].Privileges, tc.objectType), tc.expectedPrivileges)
		}
		if tc.pd.Users[0].WithGrantOption != tc.expectedGrantOption.ToBitField() {
			t.Errorf("#%d: Incorrect grant option, returned %v, expected %v",
				tcNum, privilege.ListFromBitField(tc.pd.Users[0].WithGrantOption, tc.objectType), tc.expectedGrantOption)
		}
	}
}
