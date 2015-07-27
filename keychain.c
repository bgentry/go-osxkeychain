//
//  keychain.c
//  GHKeychain
//
//  Created by Gabriel on 7/24/15.
//  Copyright (c) 2015 Gabriel Handford. All rights reserved.
//

#include "keychain.h"

/*!
 Create access for the specified application path, and ourself.
 */
OSStatus GHKeychainCreateAccessRef(CFStringRef label, CFStringRef applicationPath, SecAccessRef *accessRef) {

  // Application ref for ourself (NULL=ourself)
  SecTrustedApplicationRef myAppRef = NULL;
  OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &myAppRef);

  // Application ref for the app or executable at the specified path
  SecTrustedApplicationRef applicationRef = NULL;
  const char *applicationPathChar = CFStringGetCStringPtr(applicationPath, kCFStringEncodingUTF8);
  status = status ?: SecTrustedApplicationCreateFromPath(applicationPathChar, &applicationRef);

  if (status == noErr) {
    const void *values[] = {myAppRef, applicationRef};
    CFArrayRef trustedApplications = CFArrayCreate(NULL, (void *)values, 2, &kCFTypeArrayCallBacks);

    status = SecAccessCreate(label, trustedApplications, accessRef);

    CFRelease(trustedApplications);
  }

  CFRelease(myAppRef);
  CFRelease(applicationRef);

  return status;
}

/*!
 Create keychain item with the specified access.
 This uses SecKeychainItemCreateFromContent which allows you to specify application access on creation.
 */
OSStatus GHKeychainCreateItem(CFStringRef service, CFStringRef account, CFDataRef dataRef, SecAccessRef accessRef, SecKeychainItemRef *itemRef) {

  SecKeychainAttribute attributes[] = {
    { kSecServiceItemAttr, (UInt32)CFStringGetLength(service), (void *)CFStringGetCStringPtr(service, kCFStringEncodingUTF8) },
    { kSecAccountItemAttr, (UInt32)CFStringGetLength(account), (void *)CFStringGetCStringPtr(account, kCFStringEncodingUTF8) },
  };

  SecKeychainAttributeList attributeList = {sizeof(attributes) / sizeof(attributes[0]), attributes};
  return SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass, &attributeList, (UInt32)CFDataGetLength(dataRef), CFDataGetBytePtr(dataRef), NULL, accessRef, itemRef);
}

/*!
 Create keychain item with access for the specified application (and ourselves).
 */
OSStatus GHKeychainCreateItemForApplication(CFStringRef service, CFStringRef account, CFDataRef dataRef, CFStringRef applicationPath, SecKeychainItemRef *itemRef) {

  SecAccessRef accessRef;
  OSStatus status = GHKeychainCreateAccessRef(service, applicationPath, &accessRef);
  if (status != noErr) {
    return status;
  }

  status = GHKeychainCreateItem(service, account, dataRef, accessRef, itemRef);

  if (accessRef) CFRelease(accessRef);
  return status;
}
