//
//  TSSFuzzer.m
//  tss
//
//  Created by ethanarbuckle on 7/3/16.
//  Copyright © 2016 Ethan Arbuckle. All rights reserved.
//

#import "TSSFuzzer.h"

@implementation TSSFuzzer

- (id)init {
    
    if ((self = [super init])) {
        
        _internalFuzzingState = TSSFuzzerStateIdle;
    }
    
    return self;
}

- (NSString *)fuzzedResultsFromSeed:(NSString *)xmlSeed {
    
    NSError *swapFileError;
    NSString *xmlSeedPath = [NSString stringWithFormat:@"%@/xmlSeed.tmp", [self tempFilePath]];
    [xmlSeed writeToFile:xmlSeedPath atomically:YES encoding:NSUTF8StringEncoding error:&swapFileError];
    
    if (!swapFileError) {
        
        NSTask *fuzzTask = [[NSTask alloc] init];
        [fuzzTask setLaunchPath:@"/usr/bin/python"];
        [fuzzTask setArguments:[NSArray arrayWithObjects:kPythonFuzzerPath, xmlSeedPath, nil]];
        [fuzzTask setStandardInput:[NSPipe pipe]];
        
        NSPipe *pipe = [NSPipe pipe];
        [fuzzTask setStandardOutput:pipe];
        
        NSPipe *errorPipe = [NSPipe pipe];
        [fuzzTask setStandardError:errorPipe];
        
        [fuzzTask launch];
        [fuzzTask waitUntilExit];

        NSData *outputtedError = [[errorPipe fileHandleForReading] readDataToEndOfFile];
        if ([[[NSString alloc] initWithData:outputtedError encoding:NSUTF8StringEncoding] length] > 5 || [fuzzTask terminationStatus] != 0) {
            
            errorLog(@"\n");
            errorLog(@"[!] error with fuzzer! task finished with code %d.", [fuzzTask terminationStatus]);
            
            if (_evolvingFuzz && _internalParserOutputState == XMLParserErrorOutputFull && _ignoreFuzzerParsingErrors) {
                
                static dispatch_once_t onceToken;
                dispatch_once(&onceToken, ^{
                    
                    errorLog(@"\n");
                    errorLog(@"[**] _evolveFuzzing is currently enabled, so any following fuzz attempts will likely create malformed xml data, will partially supress incoming errors from the parser.");
                    errorLog(@"\n");
                    
                    _internalParserOutputState = XMLParserErrorOutputReduceQueued;
                    
                });
            }
            
            return @"";
        }
        
        NSData *fuzzResults = [[pipe fileHandleForReading] readDataToEndOfFile];
        NSString *fuzzedXml = [[NSString alloc] initWithData:fuzzResults encoding:NSUTF8StringEncoding];
        if ([fuzzedXml length] < 1) {
            
            errorLog(@"\n");
            errorLog(@"[!] error with fuzzer! failed to create fuzzed data.");
            return @"";
        }
        
        if ([[NSFileManager defaultManager] fileExistsAtPath:xmlSeedPath]) {
            
            [[NSFileManager defaultManager] removeItemAtPath:xmlSeedPath error:&swapFileError];
            
            if (swapFileError) {
                
                errorLog(@"\n");
                errorLog(@"[!] failed to wipe xml seed swap file. this will cause issues on the next fuzz cycle.");
            }
        }
        
        return fuzzedXml;
    }
    
    return @"";
}

- (NSString *)tempFilePath {
    
    NSURL *cachePath = [[NSFileManager defaultManager] URLForDirectory:NSCachesDirectory inDomain:NSUserDomainMask appropriateForURL:nil create:YES error:nil];
    NSString *fuzzCachePath = [NSString stringWithFormat:@"%@/fuzzer", [cachePath relativePath]];
    
    BOOL isPath;
    if (![[NSFileManager defaultManager] fileExistsAtPath:fuzzCachePath isDirectory:&isPath]) {
        
        if (!isPath) {
            
            [[NSFileManager defaultManager] removeItemAtPath:fuzzCachePath error:nil];
        }
        
        [[NSFileManager defaultManager] createDirectoryAtPath:fuzzCachePath withIntermediateDirectories:NO attributes:nil error:nil];
    }

    return fuzzCachePath;
}

- (void)beginSimpleFuzzWithBaseXMLAtPath:(NSString *)baseXMLPath maximumErrorCount:(NSUInteger)maxErrorCount {
    
    [self beginFuzzingWithBaseXMLAtPath:baseXMLPath continuously:YES cycleCount:0 maximumErrorCount:10 evolvingFuzz:YES rateLimitDuration:1.0f clearExistingFuzzCache:YES printResultsOnCompletion:YES ignoreFuzzerFormatErrors:YES];
}

- (void)beginFuzzingWithBaseXMLAtPath:(NSString *)baseXMLPath continuously:(BOOL)cycleContinuously cycleCount:(NSUInteger)cycleCount maximumErrorCount:(NSUInteger)maxErrorCount evolvingFuzz:(BOOL)evolvingFuzz rateLimitDuration:(CGFloat)rateLimit clearExistingFuzzCache:(BOOL)clearCache printResultsOnCompletion:(BOOL)printResults ignoreFuzzerFormatErrors:(BOOL)ignoreErrors {
    
    _internalFuzzingState = TSSFuzzerStateRunning;

    _cycleContinuously = cycleContinuously;
    _cycleCount = (_cycleContinuously) ? 1 : cycleCount;
    _currentCycleCount = 0;
    _evolvingFuzz = evolvingFuzz;
    _clearCache = clearCache;
    _printFuzzResults = printResults;
    _ignoreFuzzerParsingErrors = ignoreErrors;
    _rateLimit = rateLimit;
    
    _maximumErrorCount = maxErrorCount;
    _currentErrorCount = 0;
    
    _internalParserOutputState = (_suppressFuzzerErrorOutput) ? XMLParserErrorOutputReduced : XMLParserErrorOutputFull;
    
    uint total = 0;
    Ivar *ivarsBuffer = class_copyIvarList([self class], &total);
    NSMutableString *fuzzCycleSettings = [[NSMutableString alloc] initWithString:@"starting fuzzer with settings:\n"];
    for (int i = 0; i < total; i++) {
        
        [fuzzCycleSettings appendFormat:@"\t\"%s\" == \"%@\"\n", ivar_getName(ivarsBuffer[i]), [self valueForKey:[NSString stringWithCString:ivar_getName(ivarsBuffer[i]) encoding:NSUTF8StringEncoding]]];
    }
    
    NSLog(@"%@\n", fuzzCycleSettings);
    
    [self wipeExistingResultsIfNeeded];
    
    _fuzzResults = [[NSMutableArray alloc] init];
    
    NSString *baseXMLString = [[NSString alloc] initWithContentsOfFile:baseXMLPath encoding:NSUTF8StringEncoding error:nil];
    if ([baseXMLString length] < 1) {
        
        NSLog(@"\n");
        NSLog(@"[!] error with base xml provided.");
        return;
    }
    
    _baseXMLData = baseXMLString;
    _currentFuzzData = _baseXMLData;
    _baseXMLHash = [self sha1FromString:baseXMLString];
    
    if (_evolvingFuzz) {
        
        _previousFuzzedXMLData = _baseXMLData;
    }
    
    _currentCycleCount += 1;
    
    [self performTSSRequestWithXMLPostData:baseXMLString];
    
}

- (void)performTSSRequestWithXMLPostData:(NSString *)xmlPostData {
    
    [NSThread sleepForTimeInterval:_rateLimit];
    
    _previousFuzzedXMLData = xmlPostData;
    
    NSMutableURLRequest *postRequest = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kTSSServerAddress]];
    [postRequest addValue:@"text/xml" forHTTPHeaderField:@"Content-Type"];
    [postRequest setHTTPMethod:@"POST"];
    [postRequest setHTTPBody:[xmlPostData dataUsingEncoding:NSUTF8StringEncoding]];
    
    [[[NSURLSession sharedSession] dataTaskWithRequest:postRequest completionHandler:^(NSData * _Nullable responseData, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        
        if (error || [responseData length] < 1) {
            
            NSLog(@"\n");
            NSLog(@"[!] error performing tss request with xml data (%@).", xmlPostData);
            return;
        }
        
        NSString *tssResponseString = [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding];
        if ([tssResponseString length] < 1) {
            
            NSLog(@"\n");
            NSLog(@"[!] unexpected tss response (%@) using xml data (%@).", tssResponseString, xmlPostData);
            return;
        }
        
        dispatch_sync(dispatch_get_main_queue(), ^{
            
            [self TSSRequestCompletedWithResponse:tssResponseString];
        });
        
    }] resume];
    
}

- (void)TSSRequestCompletedWithResponse:(NSString *)tssResponse {
    
    if ((_currentCycleCount % 5) == 0) {
        
        [self saveFuzzResultsToFile];
    }
    
    if (_internalParserOutputState == XMLParserErrorOutputReduceQueued && !_suppressFuzzerErrorOutput) {
        
        _internalParserOutputState = XMLParserErrorOutputReduced;
    }
    
    NSError *requestError;
    if ([self statusFromResponse:tssResponse error:&requestError] != TSSResponseSuccess) {
       
        _currentErrorCount += 1;

        NSLog(@"[request #%ld] FAILED with status %ld. %@", _currentCycleCount, [requestError code], [requestError domain]);
        
        if (!_errorsRaised) {
            
            _errorsRaised = [[NSMutableArray alloc] init];
        }
        
        NSString *errorKeyName = [NSString stringWithFormat:@"%ld", [requestError code]];
        if (![_errorsRaised containsObject:errorKeyName]) {
            
            [_errorsRaised addObject:errorKeyName];
        }
    }
    
    else {
        
        NSLog(@"[request #%ld] SUCCEEDED with response length of %@.", _currentCycleCount, [_fuzzResults lastObject][@"responseLength"]);
        
        if ([_previousFuzzedXMLData isEqualToString:_baseXMLData]) {
            
            NSLog(@"\t[!] above request used orignal xml base data (%@).", _baseXMLHash);
            NSLog(@"\n");
        }
    }
        
    if (_currentCycleCount++ < _cycleCount || _cycleContinuously) {
        
        if (_currentErrorCount >= _maximumErrorCount) {
            
            NSLog(@"\n");
            NSLog(@"[!] hit max error limit of %ld, stopping.", _maximumErrorCount);
            
            [self fuzzingCompleted];
            
            return;
        }
        
        _currentFuzzData = (_evolvingFuzz) ? [self fuzzedResultsFromSeed:_previousFuzzedXMLData] : [self fuzzedResultsFromSeed:_baseXMLData];
        
        if ([_currentFuzzData length] > 0) {
            
            [self performTSSRequestWithXMLPostData:_currentFuzzData];
        }
        
        else {
            
            errorLog(@"\t[!] fuzzer created malformed data!");
            
            if (_ignoreFuzzerParsingErrors) {
                
                errorLog(@"\t\t[!] ignoring error and using invalid xml as next seed.");
            }
            
            else {
                
                errorLog(@"\t\t[!] skipping request and started fuzzing from base xml data.");
                
                _currentCycleCount += 1;
                _currentFuzzData = [self fuzzedResultsFromSeed:_baseXMLData];
            }
            
            NSLog(@"\n");
            
            [self performTSSRequestWithXMLPostData:_currentFuzzData];
        }
    }
    
    else {
        
        [self fuzzingCompleted];
    }
}

- (TSSResponseStatus)statusFromResponse:(NSString *)tssResponse error:(NSError **)requestError {
    
    NSMutableDictionary *statuses = [[NSMutableDictionary alloc] init];
    for (NSString *individualMessage in [tssResponse componentsSeparatedByString:@"&"]) {
        
        if ([[individualMessage componentsSeparatedByString:@"="] count] >= 2) {
            
            if ([[individualMessage componentsSeparatedByString:@"="][0] length] < 1 || [[individualMessage componentsSeparatedByString:@"="][1] length] < 1) {
                
                NSLog(@"\n");
                NSLog(@"[!] malformed response given!");
                return TSSResponseFailed;
            }
            
            [statuses setValue:[individualMessage componentsSeparatedByString:@"="][1] forKey:[individualMessage componentsSeparatedByString:@"="][0]];
        }
        
    }
    
    if ([[statuses allKeys] count] < 1) {
        
        NSLog(@"\n");
        NSLog(@"[!] malformed response given! (%@).", tssResponse);
        return TSSResponseFailed;
    }
    
    NSMutableArray *hashResponses = [[NSMutableArray alloc] init];
    NSArray *stringstoHash = @[tssResponse, (_currentFuzzData) ? _currentFuzzData : _baseXMLData];
    for (NSString *stringToHash in stringstoHash) {
        
        [hashResponses addObject:[self sha1FromString:stringToHash]];
    }
    
    NSDictionary *fuzzCycleResults = @{ @"didSucceed" : ([[statuses valueForKey:kTSSStatus] integerValue] == TSSResponseSuccess) ? @(1) : @(0), @"responseMessages" : [statuses copy], @"xmlPostData" : [(_evolvingFuzz) ? _previousFuzzedXMLData : _baseXMLData dataUsingEncoding:NSUTF8StringEncoding], @"responseLength" : @([tssResponse length]), @"responseHash" : hashResponses[0], @"xmlHash" : hashResponses[1] };
    
    [_fuzzResults addObject:fuzzCycleResults];
    
    if ([statuses valueForKey:kTSSStatus]) {
        
        if ([[statuses valueForKey:kTSSStatus] integerValue] != TSSResponseSuccess) {
            
            *requestError = [NSError errorWithDomain:[NSString stringWithFormat:@"raised internal error %ld, %@", [[statuses valueForKey:kTSSStatus] integerValue], ([statuses valueForKey:kTSSMessage]) ? [statuses valueForKey:kTSSMessage] : @"!"] code:[[statuses valueForKey:kTSSStatus] integerValue] userInfo:nil];
            
            return TSSResponseFailed;
        }
    }
    
    return TSSResponseSuccess;
}

- (BOOL)saveFuzzResultsToFile {
    
    NSMutableArray *existingResults = [[NSArray arrayWithContentsOfFile:[self savedResultsFilePathLocation]] mutableCopy];
    if (!existingResults) {
        
        existingResults = [[NSMutableArray alloc] init];
    }

    if ([[NSFileManager defaultManager] fileExistsAtPath:[self savedResultsFilePathLocation]]) {
        
        NSError *removeFileError;
        [[NSFileManager defaultManager] removeItemAtPath:[self savedResultsFilePathLocation] error:&removeFileError];
        
        if (removeFileError) {
            
            NSLog(@"\n");
            NSLog(@"[!] failed to overwrite existing saved fuzz results! %@ dumping to console...\n\n", removeFileError);
            for (NSDictionary *fuzzItemToDump in _fuzzResults) {
                
                NSLog(@"%@", fuzzItemToDump);
            }
            
            return NO;
        }

    }
    
    for (NSDictionary *fuzzItem in _fuzzResults) {
        
        [existingResults addObject:fuzzItem];
    }
    
    if ([existingResults count] > 0) {
        
        if (![existingResults writeToFile:[self savedResultsFilePathLocation] atomically:YES]) {
            
            NSLog(@"\n");
            NSLog(@"[!] error writing results to file! dumping to console...\n\n");
            for (NSDictionary *fuzzItemToDump in _fuzzResults) {
                
                NSLog(@"%@", fuzzItemToDump);
            }
            
            return NO;
        }
        
        return YES;
    }
    
    else {
        
        NSLog(@"[!] error, no data to write to disk");
        return NO;
    }
}

- (void)fuzzingCompleted {
    
    _internalFuzzingState = TSSFuzzerStateCompleted;
    
    NSMutableDictionary *resultsDictionary = [@{ @"successes" : @(0), @"failures" : @(0) } mutableCopy];
    for (NSDictionary *fuzzResult in _fuzzResults) {
        
        if ([fuzzResult valueForKey:@"didSucceed"] && [[fuzzResult valueForKey:@"didSucceed"] boolValue]) {
            
            [resultsDictionary setValue:@([resultsDictionary[@"successes"] integerValue] + 1) forKey:@"successes"];
        }
        
        else {
            
            [resultsDictionary setValue:@([resultsDictionary[@"failures"] integerValue] + 1) forKey:@"failures"];
        }
    }
    
    
    NSMutableString *formattedErrorList = [@"[" mutableCopy];
    for (NSString *errorCode in _errorsRaised) {
        
        [formattedErrorList appendFormat:@"%@%@", errorCode, ([_errorsRaised indexOfObject:errorCode] < ([_errorsRaised count] - 1)) ? @", " : @"]"];
    }
    
    NSLog(@"\n\nfuzzing completed.\ntotal requests: %ld\nsuccessful requests: %ld\nfailed requests: %ld\nerrors raised: %@\n\n", [_fuzzResults count], [resultsDictionary[@"successes"] integerValue], [resultsDictionary[@"failures"] integerValue], formattedErrorList);
    
    NSLog(@"\n");
    
    if ([self saveFuzzResultsToFile]) {
        
        NSLog(@"[!] results successfully written to %@", [self savedResultsFilePathLocation]);
    }
    
    if (_printFuzzResults) {
        
        [self dumpContentsOfExistingFuzzResults];
    }
    
    if (_fuzzerCompletionHandler) {
        
        _fuzzerCompletionHandler();
    }
}

- (NSString *)savedResultsFilePathLocation {
    
    return [NSString stringWithFormat:@"%@/fuzzerResults.fuzz", [self tempFilePath]];
}

- (void)wipeExistingResultsIfNeeded {

    if ([[NSFileManager defaultManager] fileExistsAtPath:[self savedResultsFilePathLocation]]) {
        
        NSLog(@"[!] previous fuzzed results found at %@. %@\n\n", [self savedResultsFilePathLocation], (_clearCache) ? @"clearing..." : @"");
        
        if (_clearCache) {
        
            NSError *fileRemoveError;
            [[NSFileManager defaultManager] removeItemAtPath:[self savedResultsFilePathLocation] error:&fileRemoveError];
            
            if (fileRemoveError) {
                
                NSLog(@"\n");
                NSLog(@"[!] failed removing exising fuzz results at path %@. %@", [self savedResultsFilePathLocation], fileRemoveError);
            }
        }
    }
}

- (void)dumpContentsOfExistingFuzzResults {
    
    NSLog(@"\n");
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:[self savedResultsFilePathLocation]]) {
        
        NSLog(@"\n");
        NSLog(@"[!] failed to find exising fuzz data at path %@.", [self savedResultsFilePathLocation]);
        return;
    }
    
    NSArray *existingResults = [NSArray arrayWithContentsOfFile:[self savedResultsFilePathLocation]];
    if (!existingResults || [existingResults count] < 1) {
        
        NSLog(@"\n");
        NSLog(@"[!] failed to find any fuzz data in file.");
        return;
    }
    
    if ([existingResults count] > 0) {
        
        NSLog(@"[self->expandXMLWhenDumping=%d] %@.", _expandXMLWhenDumping, (_expandXMLWhenDumping) ? @"expanding xml, will show full request content" : @"not expanding xml, only showing xml request content length");
        
        NSUInteger fuzzResultIndex = 0;
        while (fuzzResultIndex < [existingResults count]) {
            
            NSDictionary *fuzzInfo = existingResults[fuzzResultIndex++];
            if ([[fuzzInfo allKeys] count] > 0) {
                
                if (_supressLoggingOfFailedAttempts && ![fuzzInfo[@"didSucceed"] boolValue]) {
                    
                    continue;
                }
                
                NSString *fuzzResultPostedString = [[NSString alloc] initWithData:fuzzInfo[@"xmlPostData"] encoding:NSUTF8StringEncoding];
                NSLog(@"\n\n[%ld.] %@%@ \n\t\tresponse length: %@\n\t\tresponse hash: %@\n\t\tstatus code: %@\n\t\tmessage: \"%@\"\n\t\txml data %@ : %@\n\t\txml data hash : %@\n\n", fuzzResultIndex, ([fuzzInfo[@"didSucceed"] boolValue]) ? @"SUCCESS" : @"FAILED", ([_baseXMLHash isEqualToString:fuzzInfo[@"xmlHash"]]) ? @" (requests xml data matches original base data):" : @":", [fuzzInfo[@"responseLength"] stringValue], fuzzInfo[@"responseHash"], fuzzInfo[@"responseMessages"][kTSSStatus], fuzzInfo[@"responseMessages"][kTSSMessage], (_expandXMLWhenDumping) ? @"string" : @"length", (_expandXMLWhenDumping) ? fuzzResultPostedString : [NSString stringWithFormat:@"%ld", [fuzzResultPostedString length]], fuzzInfo[@"xmlHash"]);
            }
        }
    }
}

- (NSString *)sha1FromString:(NSString *)stringToHash {
    
    NSData *data = [stringToHash dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([data bytes], (CC_LONG)[data length], digest);
    NSMutableString *responseHashOutput = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        
        [responseHashOutput appendFormat:@"%02x", digest[i]];
    }
    
    if ([responseHashOutput length] < 5) {
        
        NSLog(@"\n");
        NSLog(@"[!] error calculating sha1 hash for %@.", stringToHash);
        
        return @"failed to calculate!";
    }
    
    return responseHashOutput;
}

@end
