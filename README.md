# memoryStatistics

## Compile

g++ --shared -fPIC -rdynamic ./*.cpp  -ldl  -o libmemStatistics.so

## Usage

LD_PRELOAD=libmemStatistics.so

```
enum SigMemTrace{
    SigMemTrace_start   = 35,
    SigMemTrace_stop    = 36,
    SigMemTrace_clear   = 37,
    SigMemTrace_dump    = 38,
    SigMemTrace_debug   = 39,
    SigMemTrace_append  = 40,
    SigMemTrace_trim    = 41
};
```

- SigMemTrace_start
    Start to do memory statistics
- SigMemTrace_stop
    Stop doing memory statistics
- SigMemTrace_clear
    Clear all memory statistics
- SigMemTrace_dump
    Dump memory statistics
- SigMemTrace_debug
    Open debug messages, such as malloc info.
- SigMemTrace_apped
    Work in append mode
- SigMemTrace_trim
    do malloc_trim once.
