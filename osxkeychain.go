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

// All string fields must have size that fits in 32 bits. All string
// fields except for Password must be encoded in UTF-8.
type GenericPasswordAttributes struct {
	ServiceName string
	AccountName string
	Password    string
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

func (attributes *GenericPasswordAttributes) CheckValidity() error {
	if err := check32BitUTF8("ServiceName", attributes.ServiceName); err != nil {
		return err
	}
	if err := check32BitUTF8("AccountName", attributes.AccountName); err != nil {
		return err
	}
	if err := check32Bit("Password", attributes.Password); err != nil {
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

func AddGenericPassword(attributes *GenericPasswordAttributes) error {
	if err := attributes.CheckValidity(); err != nil {
		return err
	}

	serviceName := C.CString(attributes.ServiceName)
	defer C.free(unsafe.Pointer(serviceName))

	accountName := C.CString(attributes.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	password := unsafe.Pointer(C.CString(attributes.Password))
	defer C.free(password)

	errCode := C.SecKeychainAddGenericPassword(
		nil, // default keychain
		C.UInt32(len(attributes.ServiceName)),
		serviceName,
		C.UInt32(len(attributes.AccountName)),
		accountName,
		C.UInt32(len(attributes.Password)),
		password,
		nil,
	)

	return newKeychainError(errCode)
}

func FindGenericPassword(attributes *GenericPasswordAttributes) (string, error) {
	if err := attributes.CheckValidity(); err != nil {
		return "", err
	}

	serviceName := C.CString(attributes.ServiceName)
	defer C.free(unsafe.Pointer(serviceName))

	accountName := C.CString(attributes.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	var passwordLength C.UInt32

	var password unsafe.Pointer

	errCode := C.SecKeychainFindGenericPassword(
		nil, // default keychain
		C.UInt32(len(attributes.ServiceName)),
		serviceName,
		C.UInt32(len(attributes.AccountName)),
		accountName,
		&passwordLength,
		&password,
		nil,
	)

	if err := newKeychainError(errCode); err != nil {
		return "", err
	}

	defer C.SecKeychainItemFreeContent(nil, password)

	return C.GoStringN((*C.char)(password), C.int(passwordLength)), nil
}

func FindAndRemoveGenericPassword(attributes *GenericPasswordAttributes) error {
	itemRef, err := findGenericPasswordItem(attributes)
	if err != nil {
		return err
	}

	defer C.CFRelease(C.CFTypeRef(itemRef))

	errCode := C.SecKeychainItemDelete(itemRef)
	return newKeychainError(errCode)
}

func ReplaceOrAddGenericPassword(attributes *GenericPasswordAttributes) error {
	itemRef, err := findGenericPasswordItem(attributes)
	if err == ErrItemNotFound {
		return AddGenericPassword(attributes)
	} else if err != nil {
		return err
	}

	defer C.CFRelease(C.CFTypeRef(itemRef))

	password := unsafe.Pointer(C.CString(attributes.Password))
	defer C.free(password)

	errCode := C.SecKeychainItemModifyAttributesAndData(
		itemRef,
		nil,
		C.UInt32(len(attributes.Password)),
		password,
	)

	return newKeychainError(errCode)
}

func findGenericPasswordItem(attributes *GenericPasswordAttributes) (itemRef C.SecKeychainItemRef, err error) {
	if err = attributes.CheckValidity(); err != nil {
		return
	}

	serviceName := C.CString(attributes.ServiceName)
	defer C.free(unsafe.Pointer(serviceName))

	accountName := C.CString(attributes.AccountName)
	defer C.free(unsafe.Pointer(accountName))

	errCode := C.SecKeychainFindGenericPassword(
		nil, // default keychain
		C.UInt32(len(attributes.ServiceName)),
		serviceName,
		C.UInt32(len(attributes.AccountName)),
		accountName,
		nil,
		nil,
		&itemRef,
	)

	err = newKeychainError(errCode)
	return
}

// The returned CFStringRef, if non-nil, must be released via CFRelease.
func _UTF8StringToCFString(s string) (C.CFStringRef, error) {
	if !utf8.ValidString(s) {
		return nil, errors.New("invalid UTF-8 string")
	}

	bytes := []byte(s)
	var p *C.UInt8
	if len(bytes) > 0 {
		p = (*C.UInt8)(&bytes[0])
	}
	return C.CFStringCreateWithBytes(nil, p, C.CFIndex(len(s)), C.kCFStringEncodingUTF8, C.false), nil
}

func _CFStringToUTF8String(s C.CFStringRef) string {
	p := C.CFStringGetCStringPtr(s, C.kCFStringEncodingUTF8)
	if p != nil {
		return C.GoString(p)
	}
	length := C.CFStringGetLength(s)
	if length == 0 {
		return ""
	}
	maxBufLen := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8)
	if maxBufLen == 0 {
		return ""
	}
	buf := make([]byte, maxBufLen)
	var usedBufLen C.CFIndex
	_ = C.CFStringGetBytes(s, C.CFRange{0, length}, C.kCFStringEncodingUTF8, C.UInt8(0), C.false, (*C.UInt8)(&buf[0]), maxBufLen, &usedBufLen)
	return string(buf[:usedBufLen])
}

// The returned CFDictionaryRef, if non-nil, must be released via CFRelease.
func mapToCFDictionary(m map[C.CFTypeRef]C.CFTypeRef) C.CFDictionaryRef {
	var keys, values []unsafe.Pointer
	for key, value := range m {
		keys = append(keys, unsafe.Pointer(key))
		values = append(values, unsafe.Pointer(value))
	}
	numValues := len(values)
	var keysPointer, valuesPointer *unsafe.Pointer
	if numValues > 0 {
		keysPointer = &keys[0]
		valuesPointer = &values[0]
	}
	return C.CFDictionaryCreate(nil, keysPointer, valuesPointer, C.CFIndex(numValues), &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
}

func _CFDictionaryToMap(cfDict C.CFDictionaryRef) (m map[C.CFTypeRef]C.CFTypeRef) {
	count := C.CFDictionaryGetCount(cfDict)
	if count > 0 {
		keys := make([]C.CFTypeRef, count)
		values := make([]C.CFTypeRef, count)
		C.CFDictionaryGetKeysAndValues(cfDict, (*unsafe.Pointer)(&keys[0]), (*unsafe.Pointer)(&values[0]))
		m = make(map[C.CFTypeRef]C.CFTypeRef, count)
		for i := C.CFIndex(0); i < count; i++ {
			m[keys[i]] = values[i]
		}
	}
	return
}

func _CFArrayToArray(cfArray C.CFArrayRef) (a []C.CFTypeRef) {
	count := C.CFArrayGetCount(cfArray)
	if count > 0 {
		a = make([]C.CFTypeRef, count)
		C.CFArrayGetValues(cfArray, C.CFRange{0, count}, (*unsafe.Pointer)(&a[0]))
	}
	return
}

func GetAllAccountNames(serviceName string) (accountNames []string, err error) {
	var serviceNameString C.CFStringRef
	if serviceNameString, err = _UTF8StringToCFString(serviceName); err != nil {
		return
	}
	defer C.CFRelease(C.CFTypeRef(serviceNameString))

	query := map[C.CFTypeRef]C.CFTypeRef{
		C.kSecClass:            C.kSecClassGenericPassword,
		C.kSecAttrService:      C.CFTypeRef(serviceNameString),
		C.kSecMatchLimit:       C.kSecMatchLimitAll,
		C.kSecReturnAttributes: C.CFTypeRef(C.kCFBooleanTrue),
	}
	queryDict := mapToCFDictionary(query)
	defer C.CFRelease(C.CFTypeRef(queryDict))

	var resultsRef C.CFTypeRef
	errCode := C.SecItemCopyMatching(queryDict, &resultsRef)
	err = newKeychainError(errCode)
	if err == ErrItemNotFound {
		return []string{}, nil
	} else if err != nil {
		return nil, err
	}

	defer C.CFRelease(resultsRef)

	results := _CFArrayToArray(C.CFArrayRef(resultsRef))
	for _, result := range results {
		m := _CFDictionaryToMap(C.CFDictionaryRef(result))
		resultServiceName := _CFStringToUTF8String(C.CFStringRef(m[C.kSecAttrService]))
		if resultServiceName != serviceName {
			err = errors.New(fmt.Sprintf("Expected service name %s, got %s", serviceName, resultServiceName))
			return
		}
		accountName := _CFStringToUTF8String(C.CFStringRef(m[C.kSecAttrAccount]))
		accountNames = append(accountNames, accountName)
	}
	return
}
