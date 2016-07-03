//
//  main.m
//  tss
//
//  Created by Ethan Arbuckle on 3/22/16.
//  Copyright © 2016 Ethan Arbuckle. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TSSFuzzer.h"

int main(int argc, const char * argv[]) {
    
    @autoreleasepool {

        __block TSSFuzzer *fuzzer = [[TSSFuzzer alloc] init];
        
        [fuzzer setFuzzerCompletionHandler:^{
            
            NSLog(@"\n");
            
            CFRunLoopStop(CFRunLoopGetMain());
        }];
        
        dispatch_async(dispatch_queue_create("com.fuzzer.fuzzthread", NULL), ^{
            
            [fuzzer beginFuzzingWithBaseXMLAtPath:@"/Users/ethanarbuckle/Desktop/baseband.xml" continuously:YES cycleCount:0 maximumErrorCount:3 evolvingFuzz:YES rateLimitDuration:1.0f clearExistingFuzzCache:YES printResultsOnCompletion:YES ignoreFuzzerFormatErrors:NO];
        });
        
        CFRunLoopRun();
    
    }
    
    return 0;
    
}