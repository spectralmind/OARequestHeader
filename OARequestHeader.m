//
//  OARequestHeader.m
//  TwitPic Uploader
//
//  Created by Gurpartap Singh on 19/06/10.
//  Copyright 2010 Gurpartap Singh. All rights reserved.
//

#import "OARequestHeader.h"

#include <CommonCrypto/CommonDigest.h>

#import "NSString+URLEncoding.h"


@interface OARequestHeader ()

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

@implementation OARequestHeader

@synthesize consumer;
@synthesize token;
@synthesize provider;
@synthesize method;
@synthesize realm;
@synthesize signature;
@synthesize signatureProvider;
@synthesize nonce;
@synthesize timestamp;

- (id)initWithProvider:(NSString *)theProvider
                method:(NSString *)theMethod
              consumer:(OAConsumer *)theConsumer
                 token:(OAToken *)theToken
                 realm:(NSString *)theRealm {
    self = [super init];
    if (self)
    {
        self.provider = theProvider;
        
        if (theMethod == nil) {
            self.method = theMethod;
        }
        else {
            self.method = @"GET";
        }
        
        self.consumer = theConsumer;
        self.token = theToken;
        self.realm = theRealm;
        self.signatureProvider = 
        [[[OAHMAC_SHA1SignatureProvider alloc] init] autorelease]; // HMAC-SHA1
    }
  
  return self;
}

- (void)dealloc {
    [consumer release];
    [token release];
    [provider release];
    [method release];
    [realm release];
    [signature release];
    [signatureProvider release];
    [nonce release];
    [timestamp release];
    
    [super dealloc];
}

- (NSString *)generateRequestHeaders {
  [self _generateTimestamp];
  [self _generateNonce];
  
    self.signature =
    [self.signatureProvider 
     signClearText:[self _signatureBaseString]
     withSecret:[NSString stringWithFormat:@"%@&%@", consumer.secret, 
                 token.secret ? token.secret : @""]];
  
	NSMutableArray *chunks = [[[NSMutableArray alloc] init] autorelease];
  
	[chunks addObject:[NSString stringWithFormat:@"realm=\"%@\"", [realm encodedURLParameterString]]];
	[chunks addObject:[NSString stringWithFormat:@"oauth_consumer_key=\"%@\"", [consumer.key encodedURLParameterString]]];
  
	NSDictionary *tokenParameters = [token parameters];
	for (NSString *k in tokenParameters) {
		[chunks addObject:[NSString stringWithFormat:@"%@=\"%@\"", k, [[tokenParameters objectForKey:k] encodedURLParameterString]]];
	}
  
	[chunks addObject:[NSString stringWithFormat:@"oauth_signature_method=\"%@\"", [[signatureProvider name] encodedURLParameterString]]];
	[chunks addObject:[NSString stringWithFormat:@"oauth_signature=\"%@\"", [signature encodedURLParameterString]]];
	[chunks addObject:[NSString stringWithFormat:@"oauth_timestamp=\"%@\"", timestamp]];
	[chunks addObject:[NSString stringWithFormat:@"oauth_nonce=\"%@\"", nonce]];
	[chunks	addObject:@"oauth_version=\"1.0\""];
	
	NSString *oauthHeader = [NSString stringWithFormat:@"OAuth %@", [chunks componentsJoinedByString:@", "]];
  
  NSLog(@"oauthHeader: %@", oauthHeader);
  
  return oauthHeader;
}


- (void)_generateTimestamp {
  self.timestamp = [NSString stringWithFormat:@"%ld", time(NULL)];
}


- (void)_generateNonce {
	const char *cStr = [[NSString stringWithFormat:@"%@%ld", timestamp, random()] UTF8String];
	unsigned char result[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1(cStr, strlen(cStr), result);
	NSMutableString *out = [NSMutableString stringWithCapacity:20];
	for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
		[out appendFormat:@"%02X", result[i]];
	}
  
  self.nonce = [[[out lowercaseString] copy] autorelease];
}


- (NSString *)_signatureBaseString {
  // OAuth Spec, Section 9.1.1 "Normalize Request Parameters"
  // Build a sorted array of both request parameters and OAuth header parameters.
	NSDictionary *tokenParameters = [token parameters];
	// 5 being the number of OAuth params in the Signature Base String
	NSMutableArray *parameterPairs = [[NSMutableArray alloc] initWithCapacity:(5 + [tokenParameters count])];
  
  [parameterPairs addObject:[[[[OARequestParameter alloc] initWithName:@"oauth_consumer_key" value:consumer.key] autorelease] URLEncodedNameValuePair]];
  [parameterPairs addObject:[[[[OARequestParameter alloc] initWithName:@"oauth_signature_method" value:[signatureProvider name]] autorelease] URLEncodedNameValuePair]];
  [parameterPairs addObject:[[[[OARequestParameter alloc] initWithName:@"oauth_timestamp" value:timestamp] autorelease] URLEncodedNameValuePair]];
  [parameterPairs addObject:[[[[OARequestParameter alloc] initWithName:@"oauth_nonce" value:nonce] autorelease] URLEncodedNameValuePair]];
  [parameterPairs addObject:[[[[OARequestParameter alloc] initWithName:@"oauth_version" value:@"1.0"] autorelease] URLEncodedNameValuePair]];
	
	for (NSString *param in tokenParameters) {
		[parameterPairs addObject:[[OARequestParameter requestParameter:param value:[tokenParameters objectForKey:param]] URLEncodedNameValuePair]];
	}
  
  NSArray *sortedPairs = [parameterPairs sortedArrayUsingSelector:@selector(compare:)];
    [parameterPairs release];
  NSString *normalizedRequestParameters = 
    [[[NSString alloc] initWithString:[sortedPairs componentsJoinedByString:@"&"]] autorelease];
  
  // OAuth Spec, Section 9.1.2 "Concatenate Request Elements"
  return [NSString stringWithFormat:@"%@&%@&%@", method, [provider encodedURLParameterString], [normalizedRequestParameters encodedURLString]];
}


@end
