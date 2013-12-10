package osxkeychain

import (
	"testing"
)

func TestInternetPassword(t *testing.T) {
	passwordVal := "longfakepassword"
	accountNameVal := "bgentry"
	serverNameVal := "HK api.heroku.com"
	pass := InternetPassword{
		ServerName:     serverNameVal,
		SecurityDomain: "api.heroku.com",
		AccountName:    accountNameVal,
		Path:           "/",
		Protocol:       ProtocolHTTPS,
		AuthType:       AuthenticationHTTPBasic,
		Password:       passwordVal,
	}
	// Add the password
	err := AddInternetPassword(&pass)
	if err != nil {
		t.Error(err)
	}
	// Try adding again, expect it to fail as a duplicate
	err = AddInternetPassword(&pass)
	if err != ErrDuplicateItem {
		t.Errorf("expected ErrDuplicateItem on 2nd save, got %s", err)
	}
	// Find the password
	pass2 := InternetPassword{
		SecurityDomain: "api.heroku.com",
		Path:           "/",
		Protocol:       ProtocolHTTPS,
		AuthType:       AuthenticationHTTPBasic,
	}
	err = FindInternetPassword(&pass2)
	if err != nil {
		t.Error(err)
	}
	if pass2.Password != passwordVal {
		t.Errorf("FindInternetPassword expected Password=%q, got %q", passwordVal, pass2.Password)
	}
	if pass2.AccountName != accountNameVal {
		t.Errorf("FindInternetPassword expected AccountName=%q, got %q", accountNameVal, pass2.AccountName)
	}
	if pass2.ServerName != serverNameVal {
		t.Errorf("FindInternetPassword expected ServerName=%q, got %q", serverNameVal, pass2.ServerName)
	}
}
