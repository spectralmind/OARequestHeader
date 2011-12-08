//
//  OARequestHeader.h
//  TwitPic Uploader
//
//  Created by Gurpartap Singh on 19/06/10.
//  Copyright 2010 Gurpartap Singh. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OAConsumer.h"
#import "OAToken.h"
#import "OAHMAC_SHA1SignatureProvider.h"
#import "OASignatureProviding.h"
#import "OARequestParameter.h"


@interface OARequestHeader : NSObject {
@protected
}

- (id)initWithProvider:(NSString *)theProvider
                method:(NSString *)theMethod
              consumer:(OAConsumer *)theConsumer
                 token:(OAToken *)theToken
                 realm:(NSString *)theRealm;

- (NSString *)generateRequestHeaders;

@property (nonatomic, retain) OAConsumer *consumer;
@property (nonatomic, retain) OAToken *token;
@property (nonatomic, retain) NSString *provider;
@property (nonatomic, retain) NSString *method;
@property (nonatomic, retain) NSString *realm;
@property (nonatomic, retain) NSString *signature;
@property (nonatomic, retain) id <OASignatureProviding, NSObject> signatureProvider;
@property (nonatomic, retain) NSString *nonce;
@property (nonatomic, retain) NSString *timestamp;

@end
