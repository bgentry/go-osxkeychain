//
//  keychain.h
//  GHKeychain
//
//  Created by Gabriel on 7/24/15.
//  Copyright (c) 2015 Gabriel Handford. All rights reserved.
//

#ifndef __GHKeychain__keychain__
#define __GHKeychain__keychain__

#include <stdio.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

OSStatus GHKeychainCreateAccessRef(CFStringRef label, CFStringRef applicationPath, SecAccessRef *accessRef);

OSStatus GHKeychainCreateItem(CFStringRef service, CFStringRef account, CFDataRef dataRef, SecAccessRef accessRef, SecKeychainItemRef *itemRef);

OSStatus GHKeychainCreateItemForApplication(CFStringRef service, CFStringRef account, CFDataRef dataRef, CFStringRef applicationPath, SecKeychainItemRef *itemRef);

#endif /* defined(__GHKeychain__keychain__) */
