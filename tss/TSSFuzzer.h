//
//  TSSFuzzer.h
//  tss
//
//  Created by ethanarbuckle on 7/3/16.
//  Copyright © 2016 Ethan Arbuckle. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>

typedef enum {
    
    TSSResponseSuccess = 0,
    TSSResponseFailed = -1
    
} TSSResponseStatus;

typedef enum {
    
    XMLParserErrorOutputFull = 0,
    XMLParserErrorOutputReduced,
    XMLParserErrorOutputReduceQueued
    
} XMLParserErrorOutputState;

typedef enum {

    TSSFuzzerStateIdle = 0,
    TSSFuzzerStateRunning,
    TSSFuzzerStateCompleted

} TSSFuzzerState;

#define kPythonFuzzerPath @"/Users/ethanarbuckle/Desktop/fuzzers/generic_xml_fuzzer.py"

#define kTSSServerAddress @"https://gs.apple.com/TSS/controller?action=2"
#define kTSSStatus @"STATUS"
#define kTSSMessage @"MESSAGE"
#define kTSSRequestString @"REQUEST_STRING"

#define errorLog(...) if (_internalParserOutputState != XMLParserErrorOutputReduced) NSLog(__VA_ARGS__); else NSLog(@"\t[*] error!");

@interface TSSFuzzer : NSObject

@property (nonatomic, retain) NSMutableArray *fuzzResults;
@property (nonatomic, retain) NSMutableArray *errorsRaised;

@property (nonatomic, retain) NSMutableDictionary *statusCodeOccurance;

@property (nonatomic) NSUInteger cycleCount;
@property (nonatomic) NSUInteger currentCycleCount;
@property (nonatomic) NSUInteger maximumErrorCount;
@property (nonatomic) NSUInteger currentErrorCount;
@property (nonatomic) NSUInteger autosaveDuration;
@property (nonatomic) NSUInteger maximumStatusRepeats;

@property (nonatomic) CGFloat rateLimit;

@property (nonatomic, retain) NSString *baseXMLData;
@property (nonatomic, retain) NSString *baseXMLHash;
@property (nonatomic, retain) NSString *previousFuzzedXMLData;
@property (nonatomic, retain) NSString *currentFuzzData;

@property (nonatomic) BOOL cycleContinuously;
@property (nonatomic) BOOL evolvingFuzz;
@property (nonatomic) BOOL clearCache;
@property (nonatomic) BOOL printFuzzResults;
@property (nonatomic) BOOL ignoreFuzzerParsingErrors;
@property (nonatomic) BOOL expandXMLWhenDumping;
@property (nonatomic) BOOL suppressFuzzerErrorOutput;
@property (nonatomic) BOOL supressLoggingOfFailedAttempts;
@property (nonatomic) BOOL onlySaveSuccessfulRequests;

@property (nonatomic) XMLParserErrorOutputState internalParserOutputState;
@property (nonatomic) TSSFuzzerState internalFuzzingState;

@property (nonatomic, copy) void (^fuzzerCompletionHandler)();

- (NSString *)fuzzedResultsFromSeed:(NSString *)xmlSeed;
- (NSString *)tempFilePath;
- (void)beginSimpleFuzzWithBaseXMLAtPath:(NSString *)baseXMLPath maximumErrorCount:(NSUInteger)maxErrorCount;
- (void)beginFuzzingWithBaseXMLAtPath:(NSString *)baseXMLPath continuously:(BOOL)cycleContinuously cycleCount:(NSUInteger)cycleCount maximumErrorCount:(NSUInteger)maxErrorCount evolvingFuzz:(BOOL)evolvingFuzz rateLimitDuration:(CGFloat)rateLimit clearExistingFuzzCache:(BOOL)clearCache printResultsOnCompletion:(BOOL)printResults ignoreFuzzerFormatErrors:(BOOL)ignoreErrors;
- (void)performTSSRequestWithXMLPostData:(NSString *)xmlPostData;
- (void)TSSRequestCompletedWithResponse:(NSString *)tssResponse;
- (TSSResponseStatus)statusFromResponse:(NSString *)tssResponse error:(NSError **)requestError;
- (BOOL)saveFuzzResultsToFile;
- (void)fuzzingCompleted;
- (NSString *)savedResultsFilePathLocation;
- (void)wipeExistingResultsIfNeeded;
- (void)dumpContentsOfExistingFuzzResults;
- (NSString *)sha1FromString:(NSString *)stringToHash;

@end
