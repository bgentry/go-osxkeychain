package osxkeychain

import (
	"testing"
)

func TestGenericPassword(t *testing.T) {
	attributes := GenericPasswordAttributes{
		ServiceName: "osxkeychain_test",
		AccountName: "test account",
	}

	// Add with a blank password.
	err := AddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Try adding again.
	err = AddGenericPassword(&attributes)
	if ke, ok := err.(*keychainError); !ok || ke.getErrCode() != errDuplicateItem {
		t.Errorf("expected ErrDuplicateItem, got %s", err)
	}

	// Find the password.
	password, err := FindGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	if password != "" {
		t.Errorf("FindGenericPassword expected empty string, got %s", password)
	}

	// Replace password with itself (a nil password).
	err = ReplaceOrAddGenericPassword(&attributes)

	// Replace password with an empty password.
	attributes.Password = ""
	err = ReplaceOrAddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Replace password with a non-empty password.
	expectedPassword := "long test password \000 with embedded nuls \000"
	attributes.Password = expectedPassword
	err = ReplaceOrAddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Find the password again.
	password, err = FindGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	if password != expectedPassword {
		t.Errorf("FindGenericPassword expected %s, got %q", expectedPassword, password)
	}

	// Remove password.
	err = FindAndRemoveGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Try removing again.
	err = FindAndRemoveGenericPassword(&attributes)
	if ke, ok := err.(*keychainError); !ok || ke.getErrCode() != errItemNotFound {
		t.Errorf("expected ErrItemNotFound, got %s", err)
	}
}
