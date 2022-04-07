// Copyright 2020 The Cockroach Authors.
//
// Licensed as a CockroachDB Enterprise file under the Cockroach Community
// License (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     https://github.com/cockroachdb/cockroach/blob/master/licenses/CCL.txt

package serverccl

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cockroachdb/cockroach/pkg/base"
	"github.com/cockroachdb/cockroach/pkg/security"
	"github.com/cockroachdb/cockroach/pkg/server"
	"github.com/cockroachdb/cockroach/pkg/sql"
	"github.com/cockroachdb/cockroach/pkg/testutils/serverutils"
	"github.com/cockroachdb/cockroach/pkg/util"
	"github.com/cockroachdb/cockroach/pkg/util/leaktest"
	"github.com/cockroachdb/cockroach/pkg/util/log"
	"github.com/cockroachdb/cockroach/pkg/util/timeutil"
	"github.com/lib/pq/oid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestVerifyPassword(t *testing.T) {
	defer leaktest.AfterTest(t)()
	defer log.Scope(t).Close(t)

	ctx := context.Background()
	s, db, _ := serverutils.StartServer(t, base.TestServerArgs{})
	defer s.Stopper().Stop(ctx)

	ie := sql.MakeInternalExecutor(
		context.Background(),
		s.(*server.TestServer).Server.PGServer().SQLServer,
		sql.MemoryMetrics{},
		s.ExecutorConfig().(sql.ExecutorConfig).Settings,
	)

	ts := s.(*server.TestServer)

	if util.RaceEnabled {
		// The default bcrypt cost makes this test approximately 30s slower when the
		// race detector is on.
		security.BcryptCost.Override(ctx, &ts.Cfg.Settings.SV, int64(bcrypt.MinCost))
	}

	//location is used for timezone testing.
	shanghaiLoc, err := timeutil.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}

	for _, user := range []struct {
		username         string
		userID           oid.Oid
		password         string
		loginFlag        string
		validUntilClause string
		qargs            []interface{}
	}{
		{"azure_diamond", 101, "hunter2", "LOGIN", "", nil},
		{"druidia", 102, "12345", "LOGIN", "", nil},

		{"richardc", 103, "12345", "NOLOGIN", "", nil},
		{"richardc2", 104, "12345", "NOSQLLOGIN", "", nil},
		{"before_epoch", 105, "12345", "", "VALID UNTIL '1969-01-01'", nil},
		{"epoch", 106, "12345", "", "VALID UNTIL '1970-01-01'", nil},
		{"cockroach", 107, "12345", "", "VALID UNTIL '2100-01-01'", nil},
		{"cthon98", 108, "12345", "", "VALID UNTIL NULL", nil},

		{"toolate", 109, "12345", "", "VALID UNTIL $1",
			[]interface{}{timeutil.Now().Add(-10 * time.Minute)}},
		{"timelord", 110, "12345", "", "VALID UNTIL $1",
			[]interface{}{timeutil.Now().Add(59 * time.Minute).In(shanghaiLoc)}},

		{"some_admin", 111, "12345", "LOGIN", "", nil},
	} {
		cmd := fmt.Sprintf(
			"CREATE ROLE %s WITH PASSWORD '%s' %s %s",
			user.username, user.password, user.loginFlag, user.validUntilClause)

		if _, err := db.Exec(cmd, user.qargs...); err != nil {
			t.Fatalf("failed to create user: %s", err)
		}
	}

	if _, err := db.Exec("GRANT admin TO some_admin"); err != nil {
		t.Fatalf("failed to grant admin: %s", err)
	}

	for _, tc := range []struct {
		testName                    string
		username                    string
		userID                      oid.Oid
		password                    string
		isSuperuser                 bool
		shouldAuthenticateSQL       bool
		shouldAuthenticateDBConsole bool
	}{
		{"valid login", "azure_diamond", 101, "hunter2", false, true, true},
		{"wrong password", "azure_diamond", 101, "hunter", false, false, false},
		{"empty password", "azure_diamond", 101, "", false, false, false},
		{"wrong emoji password", "azure_diamond", 101, "🍦", false, false, false},
		{"correct password with suffix should fail", "azure_diamond", 101, "hunter2345", false, false, false},
		{"correct password with prefix should fail", "azure_diamond", 101, "shunter2", false, false, false},
		{"wrong password all numeric", "azure_diamond", 101, "12345", false, false, false},
		{"wrong password all stars", "azure_diamond", 101, "*******", false, false, false},
		{"valid login numeric password", "druidia", 102, "12345", false, true, true},
		{"wrong password matching other user", "druidia", 102, "hunter2", false, false, false},
		{"root with empty password should fail", "root", 1, "", true, false, false},
		{"some_admin with empty password should fail", "some_admin", 111, "", true, false, false},
		{"empty username and password should fail", "", 0, "", false, false, false},
		{"username does not exist should fail", "doesntexist", 0, "zxcvbn", false, false, false},

		{"user with NOLOGIN role option should fail", "richardc", 103, "12345", false, false, false},
		// This is the one test case where SQL and DB Console login outcomes differ.
		{"user with NOSQLLOGIN role option should fail SQL but succeed on DB Console", "richardc2", 104, "12345", false, false, true},
		{"user with VALID UNTIL before the Unix epoch should fail", "before_epoch", 105, "12345", false, false, false},
		{"user with VALID UNTIL at Unix epoch should fail", "epoch", 106, "12345", false, false, false},
		{"user with VALID UNTIL future date should succeed", "cockroach", 107, "12345", false, true, true},
		{"user with VALID UNTIL 10 minutes ago should fail", "toolate", 109, "12345", false, false, false},
		{"user with VALID UNTIL future time in Shanghai time zone should succeed", "timelord", 110, "12345", false, true, true},
		{"user with VALID UNTIL NULL should succeed", "cthon98", 108, "12345", false, true, true},
	} {
		t.Run(tc.testName, func(t *testing.T) {
			execCfg := s.ExecutorConfig().(sql.ExecutorConfig)
			userID := tc.userID
			username := security.MakeSQLUsernameFromPreNormalizedString(tc.username)
			exists, canLoginSQL, canLoginDBConsole, isSuperuser, _, pwRetrieveFn, err := sql.GetUserSessionInitInfo(
				context.Background(), &execCfg, &ie, security.SQLUserInfo{Username: username, UserID: userID}, "", /* databaseName */
			)

			if err != nil {
				t.Errorf(
					"credentials %s/%s failed with error %s, wanted no error",
					tc.username,
					tc.password,
					err,
				)
			}

			valid := true
			validDBConsole := true
			expired := false

			if !exists || !canLoginSQL {
				valid = false
			}

			if !exists || !canLoginDBConsole {
				validDBConsole = false
			}
			if exists && (canLoginSQL || canLoginDBConsole) {
				var hashedPassword security.PasswordHash
				expired, hashedPassword, err = pwRetrieveFn(ctx)
				if err != nil {
					t.Errorf(
						"credentials %s/%s failed with error %s, wanted no error",
						tc.username,
						tc.password,
						err,
					)
				}

				pwCompare, err := security.CompareHashAndCleartextPassword(ctx, hashedPassword, tc.password)
				if err != nil {
					t.Error(err)
					valid = false
					validDBConsole = false
				}
				if !pwCompare {
					valid = false
					validDBConsole = false
				}
			}

			if valid && !expired != tc.shouldAuthenticateSQL {
				t.Errorf(
					"sql credentials %s/%s valid = %t, wanted %t",
					tc.username,
					tc.password,
					valid,
					tc.shouldAuthenticateSQL,
				)
			}
			if validDBConsole && !expired != tc.shouldAuthenticateDBConsole {
				t.Errorf(
					"db console credentials %s/%s valid = %t, wanted %t",
					tc.username,
					tc.password,
					validDBConsole,
					tc.shouldAuthenticateDBConsole,
				)
			}
			require.Equal(t, tc.isSuperuser, isSuperuser)
		})
	}
}
