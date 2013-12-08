package osxkeychain

import (
	"testing"
)

func TestAddInternetPassword(t *testing.T) {
	pass := InternetPassword{
		ServerName:     "HK api.heroku.com",
		SecurityDomain: "api.heroku.com",
		AccountName:    "bgentry",
		Path:           "/",
		Protocol:       ProtocolHTTPS,
		AuthType:       AuthenticationHTTPBasic,
		Password:       "longfakepassword",
	}
	err := AddInternetPassword(&pass)
	if err != nil {
		t.Error(err)
	}
	err = AddInternetPassword(&pass)
	if err != ErrDuplicateItem {
		t.Errorf("expected ErrDuplicateItem on 2nd save, got %s", err)
	}
}
