package osxkeychain

import (
	"fmt"
	"testing"
)

func TestGenericPassword(t *testing.T) {
	attributes := GenericPasswordAttributes{
		ServiceName: "osxkeychain_test with unicode テスト",
		AccountName: "test account with unicode テスト",
	}

	// Add with a blank password.
	err := AddGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}

	// Try adding again.
	err = AddGenericPassword(&attributes)
	if err != ErrDuplicateItem {
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
	expectedPassword := "long test password \000 with invalid UTF-8 \xc3\x28 and embedded nuls \000"
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
	if err != ErrItemNotFound {
		t.Errorf("expected ErrItemNotFound, got %s", err)
	}
}

// Make sure fields with invalid UTF-8 are detected properly.
func TestInvalidUTF8(t *testing.T) {
	attributes1 := GenericPasswordAttributes{
		ServiceName: "osxkeychain_test with invalid UTF-8 \xc3\x28",
		AccountName: "test account",
	}

	errServiceName := "ServiceName is not a valid UTF-8 string"

	err := AddGenericPassword(&attributes1)
	if err.Error() != errServiceName {
		t.Errorf("Expected \"%s\", got %v", errServiceName, err)
	}

	_, err = FindGenericPassword(&attributes1)
	if err.Error() != errServiceName {
		t.Errorf("Expected \"%s\", got %v", errServiceName, err)
	}

	err = ReplaceOrAddGenericPassword(&attributes1)
	if err.Error() != errServiceName {
		t.Errorf("Expected \"%s\", got %v", errServiceName, err)
	}

	err = FindAndRemoveGenericPassword(&attributes1)
	if err.Error() != errServiceName {
		t.Errorf("Expected \"%s\", got %v", errServiceName, err)
	}

	attributes2 := GenericPasswordAttributes{
		ServiceName: "osxkeychain_test",
		AccountName: "test account with invalid UTF-8 \xc3\x28",
	}

	errAccountName := "AccountName is not a valid UTF-8 string"

	err = AddGenericPassword(&attributes2)
	if err.Error() != errAccountName {
		t.Errorf("Expected \"%s\", got %v", errAccountName, err)
	}

	_, err = FindGenericPassword(&attributes2)
	if err.Error() != errAccountName {
		t.Errorf("Expected \"%s\", got %v", errAccountName, err)
	}

	err = ReplaceOrAddGenericPassword(&attributes2)
	if err.Error() != errAccountName {
		t.Errorf("Expected \"%s\", got %v", errAccountName, err)
	}

	err = FindAndRemoveGenericPassword(&attributes2)
	if err.Error() != errAccountName {
		t.Errorf("Expected \"%s\", got %v", errAccountName, err)
	}
}

func TestGetAllAccountNames(t *testing.T) {
	serviceName := "osxkeychain_test with unicode テスト"

	accountNames, err := GetAllAccountNames(serviceName)
	if err != nil {
		t.Error(err)
	}

	attributes := make([]GenericPasswordAttributes, 10)
	for i := 0; i < len(attributes); i++ {
		attributes[i] = GenericPasswordAttributes{
			ServiceName: serviceName,
			AccountName: fmt.Sprintf("test account with unicode テスト %d", i),
		}

		err := AddGenericPassword(&attributes[i])
		if err != nil {
			t.Error(err)
		}
	}

	accountNames, err = GetAllAccountNames(serviceName)
	if err != nil {
		t.Error(err)
	}

	if len(accountNames) != len(attributes) {
		t.Errorf("Expected %d accounts, got %d", len(attributes), len(accountNames))
	}

	for i := 0; i < len(accountNames); i++ {
		if accountNames[i] != attributes[i].AccountName {
			t.Errorf("Expected account name %s, got %s", attributes[i].AccountName, accountNames[i])
		}
	}

	for i := 0; i < len(attributes); i++ {
		err = FindAndRemoveGenericPassword(&attributes[i])
		if err != nil {
			t.Error(err)
		}
	}

	accountNames, err = GetAllAccountNames(serviceName)
	if err != nil {
		t.Error(err)
	}

	if len(accountNames) != 0 {
		t.Errorf("Expected no accounts, got %d", len(accountNames))
	}
}
