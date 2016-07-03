#### TSS Fuzzer. BYOXMLF (Bring your own XML fuzzer)

I recommend you don't use this, and if you do I highly recommend you channel all traffic through a VPN. 

Replace `#define kPythonFuzzerPath @"/Users/user/Desktop/fuzzers/generic_xml_fuzzer.py"` with the path to some xml fuzzer you will be using. 

Basic usage as follows:

    __block TSSFuzzer *fuzzer = [[TSSFuzzer alloc] init];
        
        [fuzzer setFuzzerCompletionHandler:^{
                        
            CFRunLoopStop(CFRunLoopGetMain());
        }];
        
        dispatch_async(dispatch_queue_create("com.fuzzer.fuzzthread", NULL), ^{
            
            [fuzzer beginFuzzingWithBaseXMLAtPath:@"/Users/ethanarbuckle/Desktop/baseband.xml" continuously:YES cycleCount:0 maximumErrorCount:10 evolvingFuzz:YES rateLimitDuration:1.0f clearExistingFuzzCache:YES printResultsOnCompletion:YES ignoreFuzzerFormatErrors:NO];
        });
        
        CFRunLoopRun();



Here's a rundown of some of the configuration options
| Property        | USage         |
| ------------- |:-------------:|
| `cycleCount`     | The amount of requests the fuzzer will make. Ignored when `cycleContinuously` is `YES`. |
| `evolvingFuzz`      | Use newly created fuzzed xml as the base for each new fuzz generation, instead of always using the original file.  |
| `maximumErrorCount` | The maximum amount of errors we can have TSS throw before stopping. Overrides `cycleCount` and `cycleContinuously`.|
| `clearCache`     | Remove any existing fuzzed results in the fuzzer's save file. New results will always be appended to existing when this is `NO`. |
| `printFuzzResults`     |  Will print all fuzz-results after fuzzing is completed when this is `YES`. It pulls results from the save file. |
| `ignoreFuzzerParsingErrors` | When set to `NO`, the fuzzer will fallback to the originally provided xml data in the event of the currently used fuzzed data being corrupted. |
| `rateLimit` | Amount of time in seconds to wait before making each TSS request. |
| `expandXMLWhenDumping` | When `YES`, the full contents of each xml string will be printed. When `NO`, it only prints the content length.| 
| `suppressFuzzerErrorOutput` | When `YES`, unneccessary error logs from the xml parser will be supressed. |
| `supressLoggingOfFailedAttempts` | When `YES`, the fuzzer will not print out fuzzing results from requests that failed.
    
All generated fuzz results are saved to `/Users/user/Library/Caches/fuzzer/fuzzerResults.fuzz`

Everything is really simple enough to be figured out.

Here's output from the fuzzer being ran with a maximum error limit of `10`:

    2016-07-03 09:46:51.525 fuzzer[20561:9012915] starting fuzzer with settings:
		"_cycleContinuously" == "1"
		"_evolvingFuzz" == "1"
		"_clearCache" == "1"
		"_printFuzzResults" == "1"
		"_ignoreFuzzerParsingErrors" == "0"
		"_expandXMLWhenDumping" == "0"
		"_suppressFuzzerErrorOutput" == "0"
		"_supressLoggingOfFailedAttempts" == "0"
		"_internalParserOutputState" == "0"
		"_internalFuzzingState" == "1"
		"_fuzzResults" == "(null)"
		"_errorsRaised" == "(null)"
		"_cycleCount" == "1"
		"_currentCycleCount" == "0"
		"_maximumErrorCount" == "10"
		"_currentErrorCount" == "0"
		"_rateLimit" == "1"
		"_baseXMLData" == "(null)"
		"_baseXMLHash" == "(null)"
		"_previousFuzzedXMLData" == "(null)"
		"_currentFuzzData" == "(null)"
		"_fuzzerCompletionHandler" == "<__NSGlobalBlock__: 0x1000091f0>"

	2016-07-03 09:46:51.560 fuzzer[20561:9012915] [!] previous fuzzed results found at /Users/ethanarbuckle/Library/Caches/fuzzer/fuzzerResults.fuzz. clearing...

	2016-07-03 09:46:53.233 fuzzer[20561:9012870] [request #1] SUCCEEDED with response length of 13598.
	2016-07-03 09:46:53.233 fuzzer[20561:9012870] 	[!] above request used orignal xml base data (16ab38893065100f0c95f3e3372e754c266132dd).
	2016-07-03 09:46:53.233 fuzzer[20561:9012870] 
	2016-07-03 09:46:54.746 fuzzer[20561:9012870] [request #2] FAILED with status 100. raised internal error 100, An internal error occurred.
	2016-07-03 09:46:55.976 fuzzer[20561:9012870] [request #3] FAILED with status 100. raised internal error 100, An internal error occurred.
	2016-07-03 09:46:57.186 fuzzer[20561:9012870] [request #4] FAILED with status 100. raised internal error 100, An internal error occurred.
	2016-07-03 09:46:57.363 fuzzer[20561:9012870] 
	2016-07-03 09:46:57.363 fuzzer[20561:9012870] [!] error with fuzzer! task finished with code 1.
	2016-07-03 09:46:57.364 fuzzer[20561:9012870] 	[!] fuzzer created malformed data!
	2016-07-03 09:46:57.364 fuzzer[20561:9012870] 		[!] skipping request and started fuzzing from base xml data.
	2016-07-03 09:46:57.432 fuzzer[20561:9012870] 
	2016-07-03 09:46:58.539 fuzzer[20561:9012870] [request #6] FAILED with status 8. raised internal error 8, An internal error occurred.
	2016-07-03 09:46:59.774 fuzzer[20561:9012870] [request #7] FAILED with status 8. raised internal error 8, An internal error occurred.
	2016-07-03 09:46:59.838 fuzzer[20561:9012870] 
	2016-07-03 09:46:59.838 fuzzer[20561:9012870] [!] error with fuzzer! task finished with code 1.
	2016-07-03 09:46:59.838 fuzzer[20561:9012870] 	[!] fuzzer created malformed data!
	2016-07-03 09:46:59.838 fuzzer[20561:9012870] 		[!] skipping request and started fuzzing from base xml data.
	2016-07-03 09:46:59.906 fuzzer[20561:9012870] 
	2016-07-03 09:47:01.007 fuzzer[20561:9012870] [request #9] FAILED with status 8. raised internal error 8, An internal error occurred.
	2016-07-03 09:47:02.255 fuzzer[20561:9012870] [request #10] FAILED with status 8. raised internal error 8, An internal error occurred.
	2016-07-03 09:47:02.322 fuzzer[20561:9012870] 
	2016-07-03 09:47:02.322 fuzzer[20561:9012870] [!] error with fuzzer! task finished with code 1.
	2016-07-03 09:47:02.322 fuzzer[20561:9012870] 	[!] fuzzer created malformed data!
	2016-07-03 09:47:02.322 fuzzer[20561:9012870] 		[!] skipping request and started fuzzing from base xml data.
	2016-07-03 09:47:02.388 fuzzer[20561:9012870] 
	2016-07-03 09:47:03.533 fuzzer[20561:9012870] [request #12] FAILED with status 100. raised internal error 100, An internal error occurred.
	2016-07-03 09:47:04.787 fuzzer[20561:9012870] [request #13] FAILED with status 100. raised internal error 100, An internal error occurred.
	2016-07-03 09:47:06.040 fuzzer[20561:9012870] [request #14] FAILED with status 100. raised internal error 100, An internal error occurred.
	2016-07-03 09:47:06.040 fuzzer[20561:9012870] 
	2016-07-03 09:47:06.040 fuzzer[20561:9012870] [!] hit max error limit of 10, stopping.
	2016-07-03 09:47:06.040 fuzzer[20561:9012870] 

	fuzzing completed.
	total requests: 11
	successful requests: 1
	failed requests: 10
	errors raised: [100, 8]

	2016-07-03 09:47:06.040 fuzzer[20561:9012870] 
	2016-07-03 09:47:06.044 fuzzer[20561:9012870] [!] results successfully written to /Users/ethanarbuckle/Library/Caches/fuzzer/fuzzerResults.fuzz
	2016-07-03 09:47:06.045 fuzzer[20561:9012870] 
	2016-07-03 09:47:06.046 fuzzer[20561:9012870] [self->expandXMLWhenDumping=0] not expanding xml, only showing xml request content length.
	2016-07-03 09:47:06.046 fuzzer[20561:9012870] 

	[1.] SUCCESS (requests xml data matches original base data): 
			response length: 13598
			response hash: 3c33a0bc36742011e70b58fa8944f04f0ceaa4ff
			status code: 0
			message: "SUCCESS"
			xml data length : 4955
			xml data hash : 16ab38893065100f0c95f3e3372e754c266132dd

	2016-07-03 09:47:06.046 fuzzer[20561:9012870] 

	[2.] FAILED: 
			response length: 46
			response hash: 82a44c7179808e0d767449c46c644f576e24f325
			status code: 100
			message: "An internal error occurred."
			xml data length : 5476
			xml data hash : 76102d63f35574fea2c29135e364302ae7787690

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[3.] FAILED: 
			response length: 46
			response hash: 82a44c7179808e0d767449c46c644f576e24f325
			status code: 100
			message: "An internal error occurred."
			xml data length : 10482
			xml data hash : fd2d47e9240f2e66f2694ddac8be54159df180c2

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[4.] FAILED: 
			response length: 46
			response hash: 82a44c7179808e0d767449c46c644f576e24f325
			status code: 100
			message: "An internal error occurred."
			xml data length : 10583
			xml data hash : cb931dc29bf28e22062d78ec1c9875e5c68f2b9c

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[5.] FAILED: 
			response length: 44
			response hash: 8e8ba0057a81ba3bb39f34a91f51fe33ce59a87a
			status code: 8
			message: "An internal error occurred."
			xml data length : 6104
			xml data hash : da39a3ee5e6b4b0d3255bfef95601890afd80709

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[6.] FAILED: 
			response length: 44
			response hash: 8e8ba0057a81ba3bb39f34a91f51fe33ce59a87a
			status code: 8
			message: "An internal error occurred."
			xml data length : 17135
			xml data hash : 2d3f6573d662336fad3d3ee6ac57c5331e41eecc

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[7.] FAILED: 
			response length: 44
			response hash: 8e8ba0057a81ba3bb39f34a91f51fe33ce59a87a
			status code: 8
			message: "An internal error occurred."
			xml data length : 5015
			xml data hash : da39a3ee5e6b4b0d3255bfef95601890afd80709

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[8.] SUCCESS (requests xml data matches original base data): 
			response length: 13598
			response hash: 3c33a0bc36742011e70b58fa8944f04f0ceaa4ff
			status code: 0
			message: "SUCCESS"
			xml data length : 4955
			xml data hash : 16ab38893065100f0c95f3e3372e754c266132dd

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[9.] FAILED: 
			response length: 46
			response hash: 82a44c7179808e0d767449c46c644f576e24f325
			status code: 100
			message: "An internal error occurred."
			xml data length : 5476
			xml data hash : 76102d63f35574fea2c29135e364302ae7787690

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[10.] FAILED: 
			response length: 46
			response hash: 82a44c7179808e0d767449c46c644f576e24f325
			status code: 100
			message: "An internal error occurred."
			xml data length : 10482
			xml data hash : fd2d47e9240f2e66f2694ddac8be54159df180c2

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[11.] FAILED: 
			response length: 46
			response hash: 82a44c7179808e0d767449c46c644f576e24f325
			status code: 100
			message: "An internal error occurred."
			xml data length : 10583
			xml data hash : cb931dc29bf28e22062d78ec1c9875e5c68f2b9c

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[12.] FAILED: 
			response length: 44
			response hash: 8e8ba0057a81ba3bb39f34a91f51fe33ce59a87a
			status code: 8
			message: "An internal error occurred."
			xml data length : 6104
			xml data hash : da39a3ee5e6b4b0d3255bfef95601890afd80709

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[13.] FAILED: 
			response length: 44
			response hash: 8e8ba0057a81ba3bb39f34a91f51fe33ce59a87a
			status code: 8
			message: "An internal error occurred."
			xml data length : 17135
			xml data hash : 2d3f6573d662336fad3d3ee6ac57c5331e41eecc

	2016-07-03 09:47:06.047 fuzzer[20561:9012870] 

	[14.] FAILED: 
			response length: 44
			response hash: 8e8ba0057a81ba3bb39f34a91f51fe33ce59a87a
			status code: 8
			message: "An internal error occurred."
			xml data length : 5015
			xml data hash : da39a3ee5e6b4b0d3255bfef95601890afd80709

	2016-07-03 09:47:06.048 fuzzer[20561:9012870] 

	[15.] FAILED: 
			response length: 44
			response hash: 8e8ba0057a81ba3bb39f34a91f51fe33ce59a87a
			status code: 8
			message: "An internal error occurred."
			xml data length : 13756
			xml data hash : 580721f3aaf43bdd1b9df10a66225d0fe28f1ee1

	2016-07-03 09:47:06.048 fuzzer[20561:9012870] 

	[16.] FAILED: 
			response length: 46
			response hash: 82a44c7179808e0d767449c46c644f576e24f325
			status code: 100
			message: "An internal error occurred."
			xml data length : 15037
			xml data hash : da39a3ee5e6b4b0d3255bfef95601890afd80709

	2016-07-03 09:47:06.048 fuzzer[20561:9012870] 

	[17.] FAILED: 
			response length: 46
			response hash: 82a44c7179808e0d767449c46c644f576e24f325
			status code: 100
			message: "An internal error occurred."
			xml data length : 20043
			xml data hash : 308b380350a0fd910716bf3fe78c182ecabfda8f

	2016-07-03 09:47:06.048 fuzzer[20561:9012870] 

	[18.] FAILED: 
			response length: 46
			response hash: 82a44c7179808e0d767449c46c644f576e24f325
			status code: 100
			message: "An internal error occurred."
			xml data length : 25267
			xml data hash : 8c9ac56b17073def1b6ea86ac6c810432bd3ee9d

	2016-07-03 09:47:06.048 fuzzer[20561:9012870] 
	Program ended with exit code: 0