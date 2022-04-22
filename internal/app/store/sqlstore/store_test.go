package sqlstore_test

import (
	"os"
	"testing"
)

var (
	databaseURL string
)

func TestMain(m *testing.M) {
	databaseURL = os.Getenv("DATAVASE_ENV")
	if databaseURL == "" {
		databaseURL = "host=localhost dbname=demo sslmode=disable user=user password=password"
	}

	os.Exit(m.Run())
}
