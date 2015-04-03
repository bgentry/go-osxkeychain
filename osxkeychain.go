package osxkeychain

/*
#cgo CFLAGS: -mmacosx-version-min=10.6 -D__MAC_OS_X_VERSION_MAX_ALLOWED=1060
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include "osxkeychain.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
	"unsafe"
)

type ProtocolType int

const (
	ProtocolHTTP ProtocolType = iota
	ProtocolHTTPS
	ProtocolAny
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
	ErrItemNotFound      = errors.New("The item cannot be found.")
)

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
	-25300: ErrItemNotFound,
}

func protocolTypeToC(t ProtocolType) (pt C.SecProtocolType) {
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

func protocolTypeToGo(proto C.CFTypeRef) ProtocolType {
	if proto == nil {
		// handle nil?
		fmt.Println("nil proto in protocolTypeToGo")
		return ProtocolAny
	}
	switch proto {
	case C.kSecAttrProtocolHTTP:
		return ProtocolHTTP
	case C.kSecAttrProtocolHTTPS:
		return ProtocolHTTPS
	}
	panic(fmt.Sprintf("unknown proto in protocolTypeToGo: %v", proto))
}

func authenticationTypeToC(t AuthenticationType) (at int) {
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

func authenticationTypeToGo(authtype C.CFTypeRef) AuthenticationType {
	if authtype == nil {
		// handle nil?
		fmt.Println("nil authtype in authenticationTypeToGo")
		return AuthenticationAny
	}
	switch authtype {
	case C.kSecAttrAuthenticationTypeHTTPBasic:
		return AuthenticationHTTPBasic
	}
	panic(fmt.Sprintf("unknown authtype in authenticationTypeToGo: %v", authtype))
}

// Adds an Internet password to the user's default keychain.
func AddInternetPassword(pass *InternetPassword) error {
	if err := pass.CheckValidity(); err != nil {
		return err
	}

	serverName := C.CString(pass.ServerName)
	defer C.free(unsafe.Pointer(serverName))

	securityDomain := C.CString(pass.SecurityDomain)
	defer C.free(unsafe.Pointer(securityDomain))

	accountName := C.CString(pass.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	path := C.CString(pass.Path)
	defer C.free(unsafe.Pointer(path))

	protocol := C.uint(protocolTypeToC(pass.Protocol))
	authtype := C.uint(authenticationTypeToC(pass.AuthType))
	password := C.CString(pass.Password)
	defer C.free(unsafe.Pointer(password))

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
		C.SecProtocolType(protocol),
		C.SecAuthenticationType(authtype),
		C.UInt32(len(pass.Password)),
		unsafe.Pointer(password),
		nil,
	)

	if errCode != C.noErr {
		if err, exists := resultCodes[int(errCode)]; exists {
			return err
		}
		return fmt.Errorf("Unmapped result code: %d", errCode)
	}

	return nil
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

	resp := InternetPassword{}
	protocol := protocolTypeToC(pass.Protocol)
	authtype := C.SecAuthenticationType(C.kSecAuthenticationTypeHTTPBasic)
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
		protocol,
		authtype,
		&cpasslen,
		&cpassword,
		&itemRef,
	)

	if errCode != C.noErr {
		if err, exists := resultCodes[int(errCode)]; exists {
			return nil, err
		}
		return nil, fmt.Errorf("Unmapped result code: %d", errCode)
	}
	defer C.CFRelease(C.CFTypeRef(itemRef))
	defer C.SecKeychainItemFreeContent(nil, cpassword)

	buf := C.GoStringN((*C.char)(cpassword), C.int(cpasslen))
	resp.Password = string(buf)

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
			return nil, err
		}
		return nil, fmt.Errorf("Unmapped result code: %d", errCode)
	}
	defer C.CFRelease(result)

	// get attributes out of attribute dictionary
	resultdict := (C.CFDictionaryRef)(result) // type cast attribute dictionary
	resp.AccountName = getCFDictValueString(resultdict, C.kSecAttrAccount)
	resp.ServerName = getCFDictValueString(resultdict, C.kSecAttrServer)
	resp.SecurityDomain = getCFDictValueString(resultdict, C.kSecAttrSecurityDomain)
	resp.Path = getCFDictValueString(resultdict, C.kSecAttrPath)

	resp.Protocol = protocolTypeToGo((C.CFTypeRef)(
		C.CFDictionaryGetValue(resultdict, unsafe.Pointer(C.kSecAttrProtocol)),
	))
	resp.AuthType = authenticationTypeToGo((C.CFTypeRef)(
		C.CFDictionaryGetValue(resultdict, unsafe.Pointer(C.kSecAttrAuthenticationType)),
	))

	// TODO: extract port number. The CFNumberRef in the dict doesn't appear to
	// have a value.
	// 	portref := (C.CFNumberRef)(C.CFDictionaryGetValue(dict, unsafe.Pointer(C.kSecAttrPort)))
	// 	if portref != nil {
	// 		var portval unsafe.Pointer
	// 		portsuccess := C.CFNumberGetValue(portref, C.kCFNumberCharType, portval)
	// 	}

	return &resp, nil
}

func getCFDictValueString(dict C.CFDictionaryRef, key C.CFTypeRef) string {
	if (int)(C.CFDictionaryGetCountOfKey(dict, unsafe.Pointer(key))) == 0 {
		fmt.Println("dict doesn't contain key", key)
	}
	// maybe try CFDictionaryGetValueIfPresent to handle non-existent keys?
	val := C.CFDictionaryGetValue(dict, unsafe.Pointer(key))
	if val != nil {
		valcstr := (*C.char)(C.CFStringGetCStringPtr((C.CFStringRef)(val), C.kCFStringEncodingUTF8))
		defer C.CFRelease(C.CFTypeRef(valcstr))
		return string(C.GoString(valcstr))
	}
	return ""
}
