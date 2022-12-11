#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int base64_valid(const char *src,size_t *count);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    std::string str = provider.ConsumeRandomLengthString();
    const char* cstr = str.c_str();
    
    base64_valid(cstr, NULL);

    return 0;
}