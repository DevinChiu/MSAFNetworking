// AFSecurityPolicyTests.m
// Copyright (c) 2011–2016 Alamofire Software Foundation ( http://alamofire.org/ )
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "AFTestCase.h"
#import "MSAFSecurityPolicy.h"

@interface AFSecurityPolicyTests : AFTestCase

@end

static SecTrustRef AFUTHTTPBinOrgServerTrust() {
    NSString *bundlePath = [[NSBundle bundleForClass:[AFSecurityPolicyTests class]] resourcePath];
    NSString *serverCertDirectoryPath = [bundlePath stringByAppendingPathComponent:@"HTTPBinOrgServerTrustChain"];

    return AFUTTrustChainForCertsInDirectory(serverCertDirectoryPath);
}

static SecTrustRef AFUTADNNetServerTrust() {
    NSString *bundlePath = [[NSBundle bundleForClass:[AFSecurityPolicyTests class]] resourcePath];
    NSString *serverCertDirectoryPath = [bundlePath stringByAppendingPathComponent:@"ADNNetServerTrustChain"];

    return AFUTTrustChainForCertsInDirectory(serverCertDirectoryPath);
}

static SecCertificateRef AFUTHTTPBinOrgCertificate() {
    NSString *certPath = [[NSBundle bundleForClass:[AFSecurityPolicyTests class]] pathForResource:@"httpbinorg_02182021" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];

    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFUTAmazonAuthorityCertificate() {
    NSString *certPath = [[NSBundle bundleForClass:NSClassFromString(@"AFSecurityPolicyTests")] pathForResource:@"Amazon" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];
    
    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFUTAmazonRootAuthorityCertificate() {
    NSString *certPath = [[NSBundle bundleForClass:NSClassFromString(@"AFSecurityPolicyTests")] pathForResource:@"Amazon Root CA 1" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];

    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFUTStarfieldServicesRootCertificate() {
    NSString *certPath = [[NSBundle bundleForClass:NSClassFromString(@"AFSecurityPolicyTests")] pathForResource:@"Starfield Services Root Certificate Authority - G2" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];
    
    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFUTSelfSignedCertificateWithoutDomain() {
    NSString *certPath = [[NSBundle bundleForClass:[AFSecurityPolicyTests class]] pathForResource:@"NoDomains" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];

    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFUTSelfSignedCertificateWithCommonNameDomain() {
    NSString *certPath = [[NSBundle bundleForClass:[AFSecurityPolicyTests class]] pathForResource:@"foobar.com" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];

    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFUTSelfSignedCertificateWithDNSNameDomain() {
    NSString *certPath = [[NSBundle bundleForClass:[AFSecurityPolicyTests class]] pathForResource:@"AltName" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];

    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecTrustRef AFUTTrustWithCertificate(SecCertificateRef certificate) {
    NSArray *certs  = @[(__bridge id)(certificate)];

    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust = NULL;
    SecTrustCreateWithCertificates((__bridge CFTypeRef)(certs), policy, &trust);
    CFRelease(policy);

    return trust;
}

@implementation AFSecurityPolicyTests

#pragma mark - Default Policy Tests
#pragma mark Default Values Test

- (void)testDefaultPolicyPinningModeIsSetToNone {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    XCTAssertTrue(policy.SSLPinningMode == AFSSLPinningModeNone, @"Pinning Mode should be set to by default");
}

- (void)testDefaultPolicyHasInvalidCertificatesAreDisabledByDefault {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    XCTAssertFalse(policy.allowInvalidCertificates, @"Invalid Certificates Should Be Disabled by Default");
}

- (void)testDefaultPolicyHasDomainNamesAreValidatedByDefault {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    XCTAssertTrue(policy.validatesDomainName, @"Domain names should be validated by default");
}

- (void)testDefaultPolicyHasNoPinnedCertificates {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    XCTAssertTrue(policy.pinnedCertificates.count == 0, @"The default policy should not have any pinned certificates");
}

#pragma mark Positive Server Trust Evaluation Tests

- (void)testDefaultPolicyDoesAllowHTTPBinOrgCertificate {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    SecTrustRef trust = AFUTHTTPBinOrgServerTrust();
    XCTAssertTrue([policy evaluateServerTrust:trust forDomain:nil], @"Valid Certificate should be allowed by default.");
}

- (void)testDefaultPolicyDoesAllowHTTPBinOrgCertificateForValidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    SecTrustRef trust = AFUTHTTPBinOrgServerTrust();
    XCTAssertTrue([policy evaluateServerTrust:trust forDomain:@"httpbin.org"], @"Valid Certificate should be allowed by default.");
}

#pragma mark Negative Server Trust Evaluation Tests

- (void)testDefaultPolicyDoesNotAllowInvalidCertificate {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    SecCertificateRef certificate = AFUTSelfSignedCertificateWithoutDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);
    XCTAssertFalse([policy evaluateServerTrust:trust forDomain:nil], @"Invalid Certificates should not be allowed");
}

- (void)testDefaultPolicyDoesNotAllowCertificateWithInvalidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    SecTrustRef trust = AFUTHTTPBinOrgServerTrust();
    XCTAssertFalse([policy evaluateServerTrust:trust forDomain:@"apple.com"], @"Certificate should not be allowed because the domain names do not match.");
}

#pragma mark - Public Key Pinning Tests
#pragma mark Default Values Tests

- (void)testPolicyWithPublicKeyPinningModeHasPinnedCertificates {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
    XCTAssertTrue(policy.pinnedCertificates > 0, @"Policy should contain default pinned certificates");
}

- (void)testPolicyWithPublicKeyPinningModeHasHTTPBinOrgPinnedCertificate {
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey withPinnedCertificates:[MSAFSecurityPolicy certificatesInBundle:bundle]];

    SecCertificateRef cert = AFUTHTTPBinOrgCertificate();
    NSData *certData = (__bridge NSData *)(SecCertificateCopyData(cert));
    CFRelease(cert);
    NSSet *set = [policy.pinnedCertificates objectsPassingTest:^BOOL(NSData *data, BOOL *stop) {
        return [data isEqualToData:certData];
    }];

    XCTAssertEqual(set.count, 1U, @"HTTPBin.org certificate not found in the default certificates");
}

#pragma mark Positive Server Trust Evaluation Tests
- (void)testPolicyWithPublicKeyPinningAllowsHTTPBinOrgServerTrustWithHTTPBinOrgLeafCertificatePinned {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];

    SecCertificateRef certificate = AFUTHTTPBinOrgCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should allow server trust");
}

- (void)testPolicyWithPublicKeyPinningAllowsHTTPBinOrgServerTrustWithHTTPBinOrgIntermediateCertificatePinned {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
    
    SecCertificateRef certificate = AFUTAmazonAuthorityCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should allow server trust");
}

- (void)testPolicyWithPublicKeyPinningAllowsHTTPBinOrgServerTrustWithHTTPBinOrgRootCertificatePinned {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
    
    SecCertificateRef certificate = AFUTAmazonRootAuthorityCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should allow server trust");
}

- (void)testPolicyWithPublicKeyPinningAllowsHTTPBinOrgServerTrustWithEntireCertificateChainPinned {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
    
    SecCertificateRef httpBinCertificate = AFUTHTTPBinOrgCertificate();
    SecCertificateRef intermediateCertificate = AFUTAmazonAuthorityCertificate();
    SecCertificateRef intermediateCertificate2 = AFUTAmazonRootAuthorityCertificate();
    SecCertificateRef rootCertificate = AFUTStarfieldServicesRootCertificate();
    [policy setPinnedCertificates:[NSSet setWithObjects:(__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate),
                                   (__bridge_transfer NSData *)SecCertificateCopyData(intermediateCertificate),
                                   (__bridge_transfer NSData *)SecCertificateCopyData(intermediateCertificate2),
                                   (__bridge_transfer NSData *)SecCertificateCopyData(rootCertificate), nil]];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should allow HTTPBinOrg server trust because at least one of the pinned certificates is valid");
    
}

- (void)testPolicyWithPublicKeyPinningAllowsHTTPBirnOrgServerTrustWithHTTPbinOrgPinnedCertificateAndAdditionalPinnedCertificates {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
    
    SecCertificateRef httpBinCertificate = AFUTHTTPBinOrgCertificate();
    SecCertificateRef selfSignedCertificate = AFUTSelfSignedCertificateWithCommonNameDomain();
    [policy setPinnedCertificates:[NSSet setWithObjects:(__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate),
                                   (__bridge_transfer NSData *)SecCertificateCopyData(selfSignedCertificate), nil]];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should allow HTTPBinOrg server trust because at least one of the pinned certificates is valid");
}

- (void)testPolicyWithPublicKeyPinningAllowsHTTPBinOrgServerTrustWithHTTPBinOrgLeafCertificatePinnedAndValidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
    
    SecCertificateRef certificate = AFUTHTTPBinOrgCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:@"httpbin.org"], @"Policy should allow server trust");
}

#pragma mark Negative Server Trust Evaluation Tests

- (void)testPolicyWithPublicKeyPinningAndNoPinnedCertificatesDoesNotAllowHTTPBinOrgServerTrust {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
    policy.pinnedCertificates = [NSSet set];
    XCTAssertFalse([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should not allow server trust because the policy is set to public key pinning and it does not contain any pinned certificates.");
}

- (void)testPolicyWithPublicKeyPinningDoesNotAllowADNServerTrustWithHTTPBinOrgPinnedCertificate {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];

    SecCertificateRef certificate = AFUTHTTPBinOrgCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertFalse([policy evaluateServerTrust:AFUTADNNetServerTrust() forDomain:nil], @"Policy should not allow ADN server trust for pinned HTTPBin.org certificate");
}

- (void)testPolicyWithPublicKeyPinningDoesNotAllowHTTPBinOrgServerTrustWithHTTPBinOrgLeafCertificatePinnedAndInvalidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];

    SecCertificateRef certificate = AFUTHTTPBinOrgCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertFalse([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:@"invaliddomainname.com"], @"Policy should not allow server trust");
}

- (void)testPolicyWithPublicKeyPinningDoesNotAllowADNServerTrustWithMultipleInvalidPinnedCertificates {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];

    SecCertificateRef httpBinCertificate = AFUTHTTPBinOrgCertificate();
    SecCertificateRef selfSignedCertificate = AFUTSelfSignedCertificateWithCommonNameDomain();
    [policy setPinnedCertificates:[NSSet setWithObjects:(__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate),
                                                        (__bridge_transfer NSData *)SecCertificateCopyData(selfSignedCertificate), nil]];
    XCTAssertFalse([policy evaluateServerTrust:AFUTADNNetServerTrust() forDomain:nil], @"Policy should not allow ADN server trust because there are no matching pinned certificates");
}

#pragma mark - Certificate Pinning Tests
#pragma mark Default Values Tests

- (void)testPolicyWithCertificatePinningModeHasPinnedCertificates {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    XCTAssertTrue(policy.pinnedCertificates > 0, @"Policy should contain default pinned certificates");
}

- (void)testPolicyWithCertificatePinningModeHasHTTPBinOrgPinnedCertificate {
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate withPinnedCertificates:[MSAFSecurityPolicy certificatesInBundle:bundle]];

    SecCertificateRef cert = AFUTHTTPBinOrgCertificate();
    NSData *certData = (__bridge NSData *)(SecCertificateCopyData(cert));
    CFRelease(cert);
    NSSet *set = [policy.pinnedCertificates objectsPassingTest:^BOOL(NSData *data, BOOL *stop) {
        return [data isEqualToData:certData];
    }];

    XCTAssertEqual(set.count, 1U, @"HTTPBin.org certificate not found in the default certificates");
}

#pragma mark Positive Server Trust Evaluation Tests
- (void)testPolicyWithCertificatePinningAllowsHTTPBinOrgServerTrustWithHTTPBinOrgLeafCertificatePinned {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];

    SecCertificateRef certificate = AFUTHTTPBinOrgCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should allow server trust");
}

- (void)testPolicyWithCertificatePinningAllowsHTTPBinOrgServerTrustWithHTTPBinOrgIntermediateCertificatePinned {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    
    SecCertificateRef certificate = AFUTAmazonAuthorityCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should allow server trust");
}

- (void)testPolicyWithCertificatePinningAllowsHTTPBinOrgServerTrustWithHTTPBinOrgRootCertificatePinned {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    
    SecCertificateRef certificate = AFUTAmazonRootAuthorityCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should allow server trust");
}

- (void)testPolicyWithCertificatePinningAllowsHTTPBinOrgServerTrustWithEntireCertificateChainPinned {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    
    SecCertificateRef httpBinCertificate = AFUTHTTPBinOrgCertificate();
    SecCertificateRef intermediateCertificate = AFUTAmazonAuthorityCertificate();
    SecCertificateRef intermediateCertificate2 = AFUTAmazonRootAuthorityCertificate();
    SecCertificateRef rootCertificate = AFUTStarfieldServicesRootCertificate();
    [policy setPinnedCertificates:[NSSet setWithObjects:(__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate),
                                   (__bridge_transfer NSData *)SecCertificateCopyData(intermediateCertificate),
                                   (__bridge_transfer NSData *)SecCertificateCopyData(intermediateCertificate2),
                                   (__bridge_transfer NSData *)SecCertificateCopyData(rootCertificate), nil]];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should allow HTTPBinOrg server trust because at least one of the pinned certificates is valid");
    
}

- (void)testPolicyWithCertificatePinningAllowsHTTPBirnOrgServerTrustWithHTTPbinOrgPinnedCertificateAndAdditionalPinnedCertificates {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    
    SecCertificateRef httpBinCertificate = AFUTHTTPBinOrgCertificate();
    SecCertificateRef selfSignedCertificate = AFUTSelfSignedCertificateWithCommonNameDomain();
    [policy setPinnedCertificates:[NSSet setWithObjects:(__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate),
                                   (__bridge_transfer NSData *)SecCertificateCopyData(selfSignedCertificate), nil]];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should allow HTTPBinOrg server trust because at least one of the pinned certificates is valid");
}

- (void)testPolicyWithCertificatePinningAllowsHTTPBinOrgServerTrustWithHTTPBinOrgLeafCertificatePinnedAndValidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    
    SecCertificateRef certificate = AFUTHTTPBinOrgCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:@"httpbin.org"], @"Policy should allow server trust");
}

#pragma mark Negative Server Trust Evaluation Tests

- (void)testPolicyWithCertificatePinningAndNoPinnedCertificatesDoesNotAllowHTTPBinOrgServerTrust {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    policy.pinnedCertificates = [NSSet set];
    XCTAssertFalse([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:nil], @"Policy should not allow server trust because the policy does not contain any pinned certificates.");
}

- (void)testPolicyWithCertificatePinningDoesNotAllowADNServerTrustWithHTTPBinOrgPinnedCertificate {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];

    SecCertificateRef certificate = AFUTHTTPBinOrgCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertFalse([policy evaluateServerTrust:AFUTADNNetServerTrust() forDomain:nil], @"Policy should not allow ADN server trust for pinned HTTPBin.org certificate");
}

- (void)testPolicyWithCertificatePinningDoesNotAllowHTTPBinOrgServerTrustWithHTTPBinOrgLeafCertificatePinnedAndInvalidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];

    SecCertificateRef certificate = AFUTHTTPBinOrgCertificate();
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(certificate)];
    XCTAssertFalse([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:@"invaliddomainname.com"], @"Policy should not allow server trust");
}

- (void)testPolicyWithCertificatePinningDoesNotAllowADNServerTrustWithMultipleInvalidPinnedCertificates {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];

    SecCertificateRef httpBinCertificate = AFUTHTTPBinOrgCertificate();
    SecCertificateRef selfSignedCertificate = AFUTSelfSignedCertificateWithCommonNameDomain();
    [policy setPinnedCertificates:[NSSet setWithObjects:(__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate),
                                                        (__bridge_transfer NSData *)SecCertificateCopyData(selfSignedCertificate), nil]];
    XCTAssertFalse([policy evaluateServerTrust:AFUTADNNetServerTrust() forDomain:nil], @"Policy should not allow ADN server trust because there are no matching pinned certificates");
}

#pragma mark - Domain Name Validation Tests
#pragma mark Positive Evaluation Tests

- (void)testThatPolicyWithoutDomainNameValidationAllowsServerTrustWithInvalidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    [policy setValidatesDomainName:NO];
    XCTAssertTrue([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:@"invalid.org"], @"Policy should allow server trust because domain name validation is disabled");
}

- (void)testThatPolicyWithDomainNameValidationAndSelfSignedCommonNameCertificateAllowsServerTrust {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];

    SecCertificateRef certificate = AFUTSelfSignedCertificateWithCommonNameDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);
    [policy setPinnedCertificates:[NSSet setWithObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)]];
    [policy setAllowInvalidCertificates:YES];

    XCTAssertTrue([policy evaluateServerTrust:trust forDomain:@"foobar.com"], @"Policy should allow server trust");
}

- (void)testThatPolicyWithDomainNameValidationAndSelfSignedDNSCertificateAllowsServerTrust {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];

    SecCertificateRef certificate = AFUTSelfSignedCertificateWithDNSNameDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);
    [policy setPinnedCertificates:[NSSet setWithObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)]];
    [policy setAllowInvalidCertificates:YES];

    XCTAssertTrue([policy evaluateServerTrust:trust forDomain:@"foobar.com"], @"Policy should allow server trust");
}

#pragma mark Negative Evaluation Tests

- (void)testThatPolicyWithDomainNameValidationDoesNotAllowServerTrustWithInvalidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    XCTAssertFalse([policy evaluateServerTrust:AFUTHTTPBinOrgServerTrust() forDomain:@"invalid.org"], @"Policy should not allow allow server trust");
}

- (void)testThatPolicyWithDomainNameValidationAndSelfSignedNoDomainCertificateDoesNotAllowServerTrust {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];

    SecCertificateRef certificate = AFUTSelfSignedCertificateWithoutDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);
    [policy setPinnedCertificates:[NSSet setWithObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)]];
    [policy setAllowInvalidCertificates:YES];

    XCTAssertFalse([policy evaluateServerTrust:trust forDomain:@"foobar.com"], @"Policy should not allow server trust");
}

#pragma mark - Self Signed Certificate Tests
#pragma mark Positive Test Cases

- (void)testThatPolicyWithInvalidCertificatesAllowedAllowsSelfSignedServerTrust {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];
    [policy setAllowInvalidCertificates:YES];

    SecCertificateRef certificate = AFUTSelfSignedCertificateWithDNSNameDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);

    XCTAssertTrue([policy evaluateServerTrust:trust forDomain:nil], @"Policy should allow server trust because invalid certificates are allowed");
}

- (void)testThatPolicyWithInvalidCertificatesAllowedAndValidPinnedCertificatesDoesAllowSelfSignedServerTrustForValidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
    [policy setAllowInvalidCertificates:YES];
    SecCertificateRef certificate = AFUTSelfSignedCertificateWithDNSNameDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);
    [policy setPinnedCertificates:[NSSet setWithObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)]];

    XCTAssertTrue([policy evaluateServerTrust:trust forDomain:@"foobar.com"], @"Policy should allow server trust because invalid certificates are allowed");
}

- (void)testThatPolicyWithInvalidCertificatesAllowedAndNoSSLPinningAndDomainNameValidationDisabledDoesAllowSelfSignedServerTrustForValidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeNone];
    [policy setAllowInvalidCertificates:YES];
    [policy setValidatesDomainName:NO];

    SecCertificateRef certificate = AFUTSelfSignedCertificateWithDNSNameDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);

    XCTAssertTrue([policy evaluateServerTrust:trust forDomain:@"foobar.com"], @"Policy should allow server trust because invalid certificates are allowed");
}

#pragma mark Negative Test Cases

- (void)testThatPolicyWithInvalidCertificatesDisabledDoesNotAllowSelfSignedServerTrust {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy defaultPolicy];

    SecCertificateRef certificate = AFUTSelfSignedCertificateWithDNSNameDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);

    XCTAssertFalse([policy evaluateServerTrust:trust forDomain:nil], @"Policy should not allow server trust because invalid certificates are not allowed");
}

- (void)testThatPolicyWithInvalidCertificatesAllowedAndNoPinnedCertificatesAndPublicKeyPinningModeDoesNotAllowSelfSignedServerTrustForValidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
    [policy setAllowInvalidCertificates:YES];
    [policy setPinnedCertificates:[NSSet set]];
    SecCertificateRef certificate = AFUTSelfSignedCertificateWithDNSNameDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);

    XCTAssertFalse([policy evaluateServerTrust:trust forDomain:@"foobar.com"], @"Policy should not allow server trust because invalid certificates are allowed but there are no pinned certificates");
}

- (void)testThatPolicyWithInvalidCertificatesAllowedAndValidPinnedCertificatesAndNoPinningModeDoesNotAllowSelfSignedServerTrustForValidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeNone];
    [policy setAllowInvalidCertificates:YES];
    SecCertificateRef certificate = AFUTSelfSignedCertificateWithDNSNameDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);
    [policy setPinnedCertificates:[NSSet setWithObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)]];

    XCTAssertFalse([policy evaluateServerTrust:trust forDomain:@"foobar.com"], @"Policy should not allow server trust because invalid certificates are allowed but there are no pinned certificates");
}

- (void)testThatPolicyWithInvalidCertificatesAllowedAndNoValidPinnedCertificatesAndNoPinningModeAndDomainValidationDoesNotAllowSelfSignedServerTrustForValidDomainName {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeNone];
    [policy setAllowInvalidCertificates:YES];
    [policy setPinnedCertificates:[NSSet set]];

    SecCertificateRef certificate = AFUTSelfSignedCertificateWithDNSNameDomain();
    SecTrustRef trust = AFUTTrustWithCertificate(certificate);

    XCTAssertFalse([policy evaluateServerTrust:trust forDomain:@"foobar.com"], @"Policy should not allow server trust because invalid certificates are allowed but there are no pinned certificates");
}

#pragma mark - NSCopying
- (void)testThatPolicyCanBeCopied {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    policy.allowInvalidCertificates = YES;
    policy.validatesDomainName = NO;
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(AFUTHTTPBinOrgCertificate())];

    MSAFSecurityPolicy *copiedPolicy = [policy copy];
    XCTAssertNotEqual(copiedPolicy, policy);
    XCTAssertEqual(copiedPolicy.allowInvalidCertificates, policy.allowInvalidCertificates);
    XCTAssertEqual(copiedPolicy.validatesDomainName, policy.validatesDomainName);
    XCTAssertEqual(copiedPolicy.SSLPinningMode, policy.SSLPinningMode);
    XCTAssertTrue([copiedPolicy.pinnedCertificates isEqualToSet:policy.pinnedCertificates]);
}

- (void)testThatPolicyCanBeEncodedAndDecoded {
    MSAFSecurityPolicy *policy = [MSAFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    policy.allowInvalidCertificates = YES;
    policy.validatesDomainName = NO;
    policy.pinnedCertificates = [NSSet setWithObject:(__bridge_transfer id)SecCertificateCopyData(AFUTHTTPBinOrgCertificate())];

    NSData *archive = [self archivedDataWithRootObject:policy];
    MSAFSecurityPolicy *unarchivedPolicy = [self unarchivedObjectOfClass:[MSAFSecurityPolicy class] fromData:archive];

    XCTAssertNotEqual(unarchivedPolicy, policy);
    XCTAssertEqual(unarchivedPolicy.allowInvalidCertificates, policy.allowInvalidCertificates);
    XCTAssertEqual(unarchivedPolicy.validatesDomainName, policy.validatesDomainName);
    XCTAssertEqual(unarchivedPolicy.SSLPinningMode, policy.SSLPinningMode);
    XCTAssertTrue([unarchivedPolicy.pinnedCertificates isEqualToSet:policy.pinnedCertificates]);
}

@end
