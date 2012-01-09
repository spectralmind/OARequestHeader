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

@property (nonatomic, strong) OAConsumer *consumer;
@property (nonatomic, strong) OAToken *token;
@property (nonatomic, strong) NSString *provider;
@property (nonatomic, strong) NSString *method;
@property (nonatomic, strong) NSString *realm;
@property (nonatomic, strong) NSString *signature;
@property (nonatomic, strong) id <OASignatureProviding, NSObject> signatureProvider;
@property (nonatomic, strong) NSString *nonce;
@property (nonatomic, strong) NSString *timestamp;

@end
