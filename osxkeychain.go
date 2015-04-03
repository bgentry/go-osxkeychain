package osxkeychain

// See https://developer.apple.com/library/mac/documentation/Security/Reference/keychainservices/index.html for the APIs used below.

// Also see https://developer.apple.com/library/ios/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html .

/*
#cgo CFLAGS: -mmacosx-version-min=10.6 -D__MAC_OS_X_VERSION_MAX_ALLOWED=1060
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
	"unsafe"
)

type ProtocolType C.SecProtocolType

// TODO: Fill this out.
const (
	ProtocolHTTP  ProtocolType = C.kSecProtocolTypeHTTP
	ProtocolHTTPS              = C.kSecProtocolTypeHTTPS
	ProtocolAny                = C.kSecProtocolTypeAny
)

type AuthenticationType C.SecAuthenticationType

// TODO: Fill this out.
const (
	AuthenticationHTTPBasic AuthenticationType = C.kSecAuthenticationTypeHTTPBasic
	AuthenticationDefault                      = C.kSecAuthenticationTypeDefault
	AuthenticationAny                          = C.kSecAuthenticationTypeAny
)

// A password for an Internet server, such as a Web or FTP server. Internet
// password items on the keychain include attributes such as the security domain
// and IP address.
//
// All string fields must have size that fits in 32 bits. All string
// fields except for Password must be encoded in UTF-8.
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

func check32Bit(paramName, paramValue string) error {
	if uint64(len(paramValue)) > math.MaxUint32 {
		return errors.New(paramName + " has size overflowing 32 bits")
	}
	return nil
}

func check32BitUTF8(paramName, paramValue string) error {
	if err := check32Bit(paramName, paramValue); err != nil {
		return err
	}
	if !utf8.ValidString(paramValue) {
		return errors.New(paramName + " is not a valid UTF-8 string")
	}
	return nil
}

func (pass *InternetPassword) CheckValidity() error {
	if err := check32BitUTF8("ServerName", pass.ServerName); err != nil {
		return err
	}
	if err := check32BitUTF8("SecurityDomain", pass.SecurityDomain); err != nil {
		return err
	}
	if err := check32BitUTF8("AccountName", pass.AccountName); err != nil {
		return err
	}
	if err := check32BitUTF8("Path", pass.Path); err != nil {
		return err
	}
	if err := check32Bit("Password", pass.Password); err != nil {
		return err
	}
	return nil
}

type keychainError C.OSStatus

// Error codes from https://developer.apple.com/library/mac/documentation/security/Reference/keychainservices/Reference/reference.html#//apple_ref/doc/uid/TP30000898-CH5g-CJBEABHG
const (
	ErrUnimplemented     keychainError = C.errSecUnimplemented
	ErrParam             keychainError = C.errSecParam
	ErrAllocate          keychainError = C.errSecAllocate
	ErrNotAvailable      keychainError = C.errSecNotAvailable
	ErrReadOnly          keychainError = C.errSecReadOnly
	ErrAuthFailed        keychainError = C.errSecAuthFailed
	ErrNoSuchKeychain    keychainError = C.errSecNoSuchKeychain
	ErrInvalidKeychain   keychainError = C.errSecInvalidKeychain
	ErrDuplicateKeychain keychainError = C.errSecDuplicateKeychain
	ErrDuplicateCallback keychainError = C.errSecDuplicateCallback
	ErrInvalidCallback   keychainError = C.errSecInvalidCallback
	ErrDuplicateItem     keychainError = C.errSecDuplicateItem
	ErrItemNotFound      keychainError = C.errSecItemNotFound
	ErrBufferTooSmall    keychainError = C.errSecBufferTooSmall
	ErrDataTooLarge      keychainError = C.errSecDataTooLarge
	ErrNoSuchAttr        keychainError = C.errSecNoSuchAttr
	ErrInvalidItemRef    keychainError = C.errSecInvalidItemRef
	ErrInvalidSearchRef  keychainError = C.errSecInvalidSearchRef
	ErrNoSuchClass       keychainError = C.errSecNoSuchClass
	ErrNoDefaultKeychain keychainError = C.errSecNoDefaultKeychain
	ErrReadOnlyAttr      keychainError = C.errSecReadOnlyAttr
	// TODO: Fill out more of these?
)

func newKeychainError(errCode C.OSStatus) error {
	if errCode == C.noErr {
		return nil
	}
	return keychainError(errCode)
}

func (ke keychainError) Error() string {
	errorMessageCFString := C.SecCopyErrorMessageString(C.OSStatus(ke), nil)
	defer C.CFRelease(C.CFTypeRef(errorMessageCFString))

	errorMessageCString := C.CFStringGetCStringPtr(errorMessageCFString, C.kCFStringEncodingASCII)

	if errorMessageCString != nil {
		return C.GoString(errorMessageCString)
	}

	return fmt.Sprintf("keychainError with unknown error code %d", C.OSStatus(ke))
}

func protocolTypeFromRef(proto C.CFTypeRef) ProtocolType {
	// TODO: Fill this out.
	switch proto {
	case C.kSecAttrProtocolHTTP:
		return ProtocolHTTP
	case C.kSecAttrProtocolHTTPS:
		return ProtocolHTTPS
	}
	panic(fmt.Sprintf("unknown proto in protocolTypeToGo: %v", proto))
}

func authenticationTypeFromRef(authType C.CFTypeRef) AuthenticationType {
	// TODO: Fill this out.
	switch authType {
	case C.kSecAttrAuthenticationTypeHTTPBasic:
		return AuthenticationHTTPBasic
	case C.kSecAttrAuthenticationTypeDefault:
		return AuthenticationDefault
	}
	panic(fmt.Sprintf("unknown authType in authenticationTypeFromStringRef: %v", authType))
}

// Adds an Internet password to the user's default keychain.
func AddInternetPassword(pass *InternetPassword) error {
	if err := pass.CheckValidity(); err != nil {
		return err
	}

	serverName := C.CString(pass.ServerName)
	defer C.free(unsafe.Pointer(serverName))

	var securityDomain *C.char
	if pass.SecurityDomain != "" {
		securityDomain = C.CString(pass.SecurityDomain)
		defer C.free(unsafe.Pointer(securityDomain))
	}

	accountName := C.CString(pass.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	path := C.CString(pass.Path)
	defer C.free(unsafe.Pointer(path))

	password := unsafe.Pointer(C.CString(pass.Password))
	defer C.free(password)

	errCode := C.SecKeychainAddInternetPassword(
		nil, // default keychain
		C.UInt32(len(pass.ServerName)),
		serverName,
		C.UInt32(len(pass.SecurityDomain)),
		securityDomain,
		C.UInt32(len(pass.AccountName)),
		accountName,
		C.UInt32(len(pass.Path)),
		path,
		C.UInt16(pass.Port),
		C.SecProtocolType(pass.Protocol),
		C.SecAuthenticationType(pass.AuthType),
		C.UInt32(len(pass.Password)),
		password,
		nil,
	)

	return newKeychainError(errCode)
}

// Finds the first Internet password item that matches the attributes you
// provide in pass. Some attributes, such as ServerName and AccountName may be
// left blank, in which case they will be ignored in the search.
//
// Returns an error if the lookup was unsuccessful.
func FindInternetPassword(pass *InternetPassword) (*InternetPassword, error) {
	if err := pass.CheckValidity(); err != nil {
		return nil, err
	}

	serverName := C.CString(pass.ServerName)
	defer C.free(unsafe.Pointer(serverName))

	var securityDomain *C.char
	if pass.SecurityDomain != "" {
		securityDomain = C.CString(pass.SecurityDomain)
		defer C.free(unsafe.Pointer(securityDomain))
	}

	accountName := C.CString(pass.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	path := C.CString(pass.Path)
	defer C.free(unsafe.Pointer(path))

	var passwordLength C.UInt32
	var password unsafe.Pointer
	var itemRef C.SecKeychainItemRef

	errCode := C.SecKeychainFindInternetPassword(
		nil, // default keychain
		C.UInt32(len(pass.ServerName)),
		serverName,
		C.UInt32(len(pass.SecurityDomain)),
		securityDomain,
		C.UInt32(len(pass.AccountName)),
		accountName,
		C.UInt32(len(pass.Path)),
		path,
		C.UInt16(pass.Port),
		C.SecProtocolType(pass.Protocol),
		C.SecAuthenticationType(pass.AuthType),
		&passwordLength,
		&password,
		&itemRef,
	)

	if err := newKeychainError(errCode); err != nil {
		return nil, err
	}

	defer C.CFRelease(C.CFTypeRef(itemRef))
	defer C.SecKeychainItemFreeContent(nil, password)

	resp := InternetPassword{}
	resp.Password = C.GoStringN((*C.char)(password), C.int(passwordLength))

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
	if err := newKeychainError(errCode); err != nil {
		return nil, err
	}
	defer C.CFRelease(result)

	// get attributes out of attribute dictionary
	resultdict := (C.CFDictionaryRef)(result) // type cast attribute dictionary
	resp.ServerName = getCFDictValueUTF8String(resultdict, C.kSecAttrServer)
	resp.SecurityDomain = getCFDictValueUTF8String(resultdict, C.kSecAttrSecurityDomain)
	resp.AccountName = getCFDictValueUTF8String(resultdict, C.kSecAttrAccount)
	resp.Path = getCFDictValueUTF8String(resultdict, C.kSecAttrPath)
	resp.Port = (int)(getCFDictValueInt32(resultdict, C.kSecAttrPort))
	resp.Protocol = protocolTypeFromRef(getCFDictValueRef(resultdict, C.kSecAttrProtocol))
	resp.AuthType = authenticationTypeFromRef(getCFDictValueRef(resultdict, C.kSecAttrAuthenticationType))

	return &resp, nil
}

func getCFDictValueRef(dict C.CFDictionaryRef, key C.CFTypeRef) C.CFTypeRef {
	return (C.CFTypeRef)(C.CFDictionaryGetValue(dict, unsafe.Pointer(key)))
}

func getCFDictValueUTF8String(dict C.CFDictionaryRef, key C.CFTypeRef) string {
	val := getCFDictValueRef(dict, key)
	if val == nil {
		return ""
	}
	valcstr := C.CFStringGetCStringPtr((C.CFStringRef)(val), C.kCFStringEncodingUTF8)
	return C.GoString(valcstr)
}

func getCFDictValueInt32(dict C.CFDictionaryRef, key C.CFTypeRef) (ret int32) {
	val := getCFDictValueRef(dict, key)
	if val == nil {
		return
	}
	if C.CFNumberGetValue((C.CFNumberRef)(val), C.kCFNumberSInt32Type, unsafe.Pointer(&ret)) == C.false {
		ret = 0
		return
	}
	return
}
