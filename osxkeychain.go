package osxkeychain

/*
#cgo CFLAGS: -mmacosx-version-min=10.6 -D__MAC_OS_X_VERSION_MAX_ALLOWED=1060
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include "osxkeychain.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

type ProtocolType int

const (
	ProtocolHTTP ProtocolType = iota
	ProtocolHTTPS
)

type AuthenticationType int

const (
	AuthenticationHTTPBasic AuthenticationType = iota
	AuthenticationDefault
	AuthenticationAny
)

// A password for an Internet server, such as a Web or FTP server. Internet
// password items on the keychain include attributes such as the security domain
// and IP address.
type InternetPassword struct {
	ServerName     string
	SecurityDomain string
	AccountName    string
	Path           string
	Port           int // Use 0 to ignore
	Password       string
	Protocol       ProtocolType
	AuthType       AuthenticationType
}

// Error codes from https://developer.apple.com/library/mac/documentation/security/Reference/keychainservices/Reference/reference.html#//apple_ref/doc/uid/TP30000898-CH5g-CJBEABHG
var (
	ErrUnimplemented     = errors.New("Function or operation not implemented.")
	ErrParam             = errors.New("One or more parameters passed to the function were not valid.")
	ErrAllocate          = errors.New("Failed to allocate memory.")
	ErrNotAvailable      = errors.New("No trust results are available.")
	ErrReadOnly          = errors.New("Read only error.")
	ErrAuthFailed        = errors.New("Authorization/Authentication failed.")
	ErrNoSuchKeychain    = errors.New("The keychain does not exist.")
	ErrInvalidKeychain   = errors.New("The keychain is not valid.")
	ErrDuplicateKeychain = errors.New("A keychain with the same name already exists.")
	ErrDuplicateCallback = errors.New("More than one callback of the same name exists.")
	ErrInvalidCallback   = errors.New("The callback is not valid.")
	ErrDuplicateItem     = errors.New("The item already exists.")
)

var resultCodes map[int]error = map[int]error{
	-4:     ErrUnimplemented,
	-50:    ErrParam,
	-108:   ErrAllocate,
	-25291: ErrNotAvailable,
	-25292: ErrReadOnly,
	-25293: ErrAuthFailed,
	-25294: ErrNoSuchKeychain,
	-25295: ErrInvalidKeychain,
	-25296: ErrDuplicateKeychain,
	-25297: ErrDuplicateCallback,
	-25298: ErrInvalidCallback,
	-25299: ErrDuplicateItem,
}

func getProtocolType(t ProtocolType) (pt int) {
	switch t {
	case ProtocolHTTP:
		pt = C.kSecProtocolTypeHTTP
	case ProtocolHTTPS:
		pt = C.kSecProtocolTypeHTTPS
	default:
		pt = C.kSecProtocolTypeAny
	}
	return
}

func getAuthenticationType(t AuthenticationType) (at int) {
	switch t {
	case AuthenticationHTTPBasic:
		at = C.kSecAuthenticationTypeHTTPBasic
	case AuthenticationAny:
		at = C.kSecAuthenticationTypeAny
	default:
		at = C.kSecAuthenticationTypeDefault
	}
	return
}

// Adds an Internet password to the user's default keychain.
func AddInternetPassword(pass *InternetPassword) error {
	protocol := C.uint(getProtocolType(pass.Protocol))
	authtype := C.uint(getAuthenticationType(pass.AuthType))
	cpassword := C.CString(pass.Password)
	var itemRef C.SecKeychainItemRef

	errCode := C.SecKeychainAddInternetPassword(
		nil, // default keychain
		C.UInt32(len(pass.ServerName)),
		C.CString(pass.ServerName),
		C.UInt32(len(pass.SecurityDomain)),
		C.CString(pass.SecurityDomain),
		C.UInt32(len(pass.AccountName)),
		C.CString(pass.AccountName),
		C.UInt32(len(pass.Path)),
		C.CString(pass.Path),
		C.UInt16(pass.Port),
		C.SecProtocolType(protocol),
		C.SecAuthenticationType(authtype),
		C.UInt32(len(pass.Password)),
		unsafe.Pointer(&cpassword),
		&itemRef,
	)
	if errCode != C.noErr {
		if err, exists := resultCodes[int(errCode)]; exists {
			return err
		}
		return fmt.Errorf("Unmapped result code: %d", errCode)
	}
	defer C.CFRelease(C.CFTypeRef(itemRef))

	fmt.Println(itemRef)
	return nil
}

// Finds the first Internet password item that matches the attributes you
// provide in pass. Some attributes, such as ServerName and AccountName may be
// left blank, in which case they will be ignored in the search.
//
// Returns an error if the lookup was unsuccessful.
func FindInternetPassword(pass *InternetPassword) error {
	protocol := C.uint(getProtocolType(pass.Protocol))
	authtype := C.uint(C.kSecAuthenticationTypeHTTPBasic)
	var cpassword unsafe.Pointer
	var cpasslen C.UInt32
	var itemRef C.SecKeychainItemRef

	errCode := C.SecKeychainFindInternetPassword(
		nil, // default keychain
		C.UInt32(len(pass.ServerName)),
		C.CString(pass.ServerName),
		C.UInt32(len(pass.SecurityDomain)),
		C.CString(pass.SecurityDomain),
		C.UInt32(len(pass.AccountName)),
		C.CString(pass.AccountName),
		C.UInt32(len(pass.Path)),
		C.CString(pass.Path),
		C.UInt16(pass.Port),
		C.SecProtocolType(protocol),
		C.SecAuthenticationType(authtype),
		&cpasslen,
		&cpassword,
		&itemRef,
	)

	if errCode != C.noErr {
		if err, exists := resultCodes[int(errCode)]; exists {
			return err
		}
		return fmt.Errorf("Unmapped result code: %d", errCode)
	}
	defer C.CFRelease(C.CFTypeRef(itemRef))
	defer C.SecKeychainItemFreeContent(nil, cpassword)

	cp2 := (**C.char)(cpassword)
	buf := C.GoStringN(*cp2, C.int(cpasslen))
	pass.Password = string(buf)

	// Get remaining attributes
	items := C.CFArrayCreateMutable(nil, 1, nil)
	defer C.CFRelease(C.CFTypeRef(items))
	C.CFArrayAppendValue(items, unsafe.Pointer(itemRef))
	dict := C.CFDictionaryCreateMutable(nil, 0, nil, nil)
	defer C.CFRelease(C.CFTypeRef(dict))
	C.CFDictionaryAddValue(dict, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassInternetPassword))
	C.CFDictionaryAddValue(dict, unsafe.Pointer(C.kSecMatchItemList), unsafe.Pointer(items))
	C.CFDictionaryAddValue(dict, unsafe.Pointer(C.kSecReturnAttributes), unsafe.Pointer(C.kCFBooleanTrue))

	var result C.CFTypeRef = nil
	errCode = C.SecItemCopyMatching(dict, &result)
	if errCode != C.noErr {
		if err, exists := resultCodes[int(errCode)]; exists {
			return err
		}
		return fmt.Errorf("Unmapped result code: %d", errCode)
	}
	defer C.CFRelease(result)

	// Get attributes out of result dictionary
	resultdict := (C.CFDictionaryRef)(result)
	val := C.CFDictionaryGetValue(resultdict, unsafe.Pointer(C.kSecAttrAccount))
	if val != nil {
		valcstr := (*C.char)(C.CFStringGetCStringPtr((C.CFStringRef)(val), C.kCFStringEncodingUTF8))
		defer C.CFRelease(C.CFTypeRef(valcstr))
		buf := C.GoString(valcstr)
		pass.AccountName = string(buf)
	}

	return nil
}
