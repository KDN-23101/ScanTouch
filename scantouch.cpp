/**
 * ScanTouch — Zero-Dependency Standalone Antivirus Scanner
 *
 * Compile on Linux/macOS:
 *   g++ -std=c++17 -O2 -o scantouch scantouch.cpp && ./scantouch scan /tmp
 *
 * Compile on Windows (MinGW/g++):
 *   g++ -std=c++17 -O2 -o scantouch.exe scantouch.cpp
 *
 * Compile on Windows (MSVC):
 *   cl /std:c++17 /O2 /EHsc scantouch.cpp /Fe:scantouch.exe
 *
 * NO external libraries needed. Pure C++17 stdlib only.
 */

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <ctime>
#include <string>
#include <vector>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <optional>
#include <unordered_map>

namespace fs = std::filesystem;

// ─── Windows console: enable UTF-8 output + ANSI color ───────────────────────
#if defined(_WIN32)
  #include <io.h>
  #include <windows.h>
  #define IS_TTY() (_isatty(_fileno(stdout)))

  static void winConsoleInit() {
      // Enable UTF-8 output so box-drawing characters render correctly
      SetConsoleOutputCP(CP_UTF8);
      SetConsoleCP(CP_UTF8);
      // Enable ANSI escape codes on Windows 10+
      HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
      if (hOut != INVALID_HANDLE_VALUE) {
          DWORD mode = 0;
          if (GetConsoleMode(hOut, &mode))
              SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
      }
  }
#else
  #include <unistd.h>
  #define IS_TTY() (isatty(fileno(stdout)))
  static void winConsoleInit() {}
#endif

struct Color {
    static bool enabled;
    static const char* red()    { return enabled ? "\033[31m" : ""; }
    static const char* yellow() { return enabled ? "\033[33m" : ""; }
    static const char* green()  { return enabled ? "\033[32m" : ""; }
    static const char* cyan()   { return enabled ? "\033[36m" : ""; }
    static const char* bold()   { return enabled ? "\033[1m"  : ""; }
    static const char* reset()  { return enabled ? "\033[0m"  : ""; }
};
bool Color::enabled = false;

// ═══════════════════════════════════════════════════════════════════════════════
// Pure C++ SHA-256 (FIPS 180-4)
// ═══════════════════════════════════════════════════════════════════════════════
namespace sha256_impl {
static constexpr uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static inline uint32_t rotr(uint32_t x,int n){return(x>>n)|(x<<(32-n));}
static inline uint32_t ch(uint32_t x,uint32_t y,uint32_t z){return(x&y)^(~x&z);}
static inline uint32_t maj(uint32_t x,uint32_t y,uint32_t z){return(x&y)^(x&z)^(y&z);}
static inline uint32_t S0(uint32_t x){return rotr(x,2)^rotr(x,13)^rotr(x,22);}
static inline uint32_t S1(uint32_t x){return rotr(x,6)^rotr(x,11)^rotr(x,25);}
static inline uint32_t G0(uint32_t x){return rotr(x,7)^rotr(x,18)^(x>>3);}
static inline uint32_t G1(uint32_t x){return rotr(x,17)^rotr(x,19)^(x>>10);}

struct SHA256 {
    uint32_t h[8]; uint8_t buf[64]; uint64_t bits; size_t len;
    SHA256(){reset();}
    void reset(){
        h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
        h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19;
        bits=0;len=0;
    }
    void block(const uint8_t* b){
        uint32_t w[64];
        for(int i=0;i<16;i++) w[i]=(uint32_t(b[i*4])<<24)|(uint32_t(b[i*4+1])<<16)|(uint32_t(b[i*4+2])<<8)|b[i*4+3];
        for(int i=16;i<64;i++) w[i]=G1(w[i-2])+w[i-7]+G0(w[i-15])+w[i-16];
        uint32_t a=h[0],b2=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],t=h[7];
        for(int i=0;i<64;i++){uint32_t T1=t+S1(e)+ch(e,f,g)+K[i]+w[i],T2=S0(a)+maj(a,b2,c);
            t=g;g=f;f=e;e=d+T1;d=c;c=b2;b2=a;a=T1+T2;}
        h[0]+=a;h[1]+=b2;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=t;
    }
    void update(const uint8_t* data,size_t n){
        while(n>0){size_t take=std::min(n,64-len);memcpy(buf+len,data,take);
            len+=take;data+=take;n-=take;bits+=take*8;
            if(len==64){block(buf);len=0;}}
    }
    std::array<uint8_t,32> digest(){
        buf[len++]=0x80;
        if(len>56){memset(buf+len,0,64-len);block(buf);len=0;}
        memset(buf+len,0,56-len);
        for(int i=0;i<8;i++) buf[56+i]=uint8_t(bits>>(56-8*i));
        block(buf);
        std::array<uint8_t,32> o;
        for(int i=0;i<8;i++){o[i*4]=(h[i]>>24)&0xff;o[i*4+1]=(h[i]>>16)&0xff;o[i*4+2]=(h[i]>>8)&0xff;o[i*4+3]=h[i]&0xff;}
        return o;
    }
};
} // sha256_impl

// ═══════════════════════════════════════════════════════════════════════════════
// Pure C++ MD5 (RFC 1321)
// ═══════════════════════════════════════════════════════════════════════════════
namespace md5_impl {
static constexpr uint32_t T[64]={
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static constexpr uint8_t S[64]={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
static inline uint32_t rotl(uint32_t x,int n){return(x<<n)|(x>>(32-n));}
struct MD5{
    uint32_t s[4];uint8_t buf[64];uint64_t bits;size_t len;
    MD5(){reset();}
    void reset(){s[0]=0x67452301;s[1]=0xefcdab89;s[2]=0x98badcfe;s[3]=0x10325476;bits=0;len=0;}
    void block(const uint8_t* b){
        uint32_t M[16],a=s[0],b2=s[1],c=s[2],d=s[3];
        for(int i=0;i<16;i++) M[i]=uint32_t(b[i*4])|(uint32_t(b[i*4+1])<<8)|(uint32_t(b[i*4+2])<<16)|(uint32_t(b[i*4+3])<<24);
        for(int i=0;i<64;i++){uint32_t F,g;
            if(i<16){F=(b2&c)|(~b2&d);g=i;}
            else if(i<32){F=(d&b2)|(~d&c);g=(5*i+1)%16;}
            else if(i<48){F=b2^c^d;g=(3*i+5)%16;}
            else{F=c^(b2|~d);g=(7*i)%16;}
            uint32_t tmp=d;d=c;c=b2;b2=b2+rotl(a+F+T[i]+M[g],S[i]);a=tmp;}
        s[0]+=a;s[1]+=b2;s[2]+=c;s[3]+=d;
    }
    void update(const uint8_t* data,size_t n){
        while(n>0){size_t take=std::min(n,64-len);memcpy(buf+len,data,take);
            len+=take;data+=take;n-=take;bits+=take*8;if(len==64){block(buf);len=0;}}
    }
    std::array<uint8_t,16> digest(){
        buf[len++]=0x80;
        if(len>56){memset(buf+len,0,64-len);block(buf);len=0;}
        memset(buf+len,0,56-len);
        for(int i=0;i<8;i++) buf[56+i]=uint8_t(bits>>(8*i));
        block(buf);
        std::array<uint8_t,16> o;
        for(int i=0;i<4;i++){o[i*4]=s[i]&0xff;o[i*4+1]=(s[i]>>8)&0xff;o[i*4+2]=(s[i]>>16)&0xff;o[i*4+3]=(s[i]>>24)&0xff;}
        return o;
    }
};
} // md5_impl

// ─── Hash helpers ─────────────────────────────────────────────────────────────
static std::string toHex(const uint8_t* d,size_t n){
    std::string s;s.reserve(n*2);
    static const char h[]="0123456789abcdef";
    for(size_t i=0;i<n;i++){s+=h[(d[i]>>4)&0xf];s+=h[d[i]&0xf];}
    return s;
}
static std::string sha256Buf(const uint8_t* d,size_t n){sha256_impl::SHA256 c;c.update(d,n);auto r=c.digest();return toHex(r.data(),32);}
static std::string md5Buf(const uint8_t* d,size_t n){md5_impl::MD5 c;c.update(d,n);auto r=c.digest();return toHex(r.data(),16);}
static double entropy(const uint8_t* d,size_t n){
    if(!n)return 0.0;uint64_t f[256]={};for(size_t i=0;i<n;i++)f[d[i]]++;
    double e=0.0;for(int i=0;i<256;i++){if(!f[i])continue;double p=(double)f[i]/n;e-=p*std::log2(p);}return e;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Threat model
// ═══════════════════════════════════════════════════════════════════════════════
enum class Sev{Clean=0,Info=1,Low=2,Medium=3,High=4,Critical=5};
static const char* sevStr(Sev s){
    switch(s){case Sev::Clean:return"CLEAN";case Sev::Info:return"INFO";
    case Sev::Low:return"LOW";case Sev::Medium:return"MEDIUM";
    case Sev::High:return"HIGH";case Sev::Critical:return"CRITICAL";}return"?";
}
struct Threat{
    std::string name;
    std::string details;
    Sev sev=Sev::Clean;
    int score=0;
};
struct FileResult{
    fs::path path;std::string sha256,md5,ftype;
    int64_t size=0;double ent=0.0;
    std::vector<Threat> threats;
    bool isThreat()const{return!threats.empty();}
};

// ═══════════════════════════════════════════════════════════════════════════════
// Known-bad hash DB (SHA-256 and MD5) — zero false positive risk
// ═══════════════════════════════════════════════════════════════════════════════
static const std::unordered_map<std::string,std::pair<std::string,Sev>> KNOWN = {
    {"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", {"EICAR-Test-File",       Sev::Info}},
    {"cf8bd9dfddff007f75adf4c2be48005cea317c62018ae3b435b48e0f4c99c29e", {"EICAR-Test-File(LF)",   Sev::Info}},
    {"84c82835a5d21bbcf75a61706d8ab549",                                  {"Ransom.WannaCry",       Sev::Critical}},
    {"027cc450ef5f8c5f653329641ec1fed9",                                  {"Ransom.Petya.NotPetya", Sev::Critical}},
};

// ═══════════════════════════════════════════════════════════════════════════════
// Boyer-Moore-Horspool byte search
// ═══════════════════════════════════════════════════════════════════════════════
static bool bmhFind(const uint8_t* hay,size_t hlen,const uint8_t* ned,size_t nlen){
    if(!nlen||nlen>hlen)return false;
    size_t skip[256];std::fill(skip,skip+256,nlen);
    for(size_t i=0;i<nlen-1;i++)skip[ned[i]]=nlen-1-i;
    size_t pos=nlen-1;
    while(pos<hlen){
        size_t j=nlen-1,cur=pos;
        while(hay[cur]==ned[j]){if(!j)return true;--cur;--j;}
        pos+=skip[hay[pos]];
    }
    return false;
}
static bool strFind(const uint8_t* d,size_t n,const char* s){
    return bmhFind(d,n,reinterpret_cast<const uint8_t*>(s),strlen(s));
}

static inline uint8_t toLowerAscii(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (c + 32) : c;
}

static bool bmhFindNoCase(const uint8_t* hay, size_t hlen, const uint8_t* ned, size_t nlen) {
    if(!nlen || nlen > hlen) return false;
    size_t skip[256];
    std::fill(skip, skip + 256, nlen);
    for(size_t i = 0; i < nlen - 1; i++) skip[toLowerAscii(ned[i])] = nlen - 1 - i;
    size_t pos = nlen - 1;
    while(pos < hlen) {
        size_t j = nlen - 1, cur = pos;
        while(toLowerAscii(hay[cur]) == toLowerAscii(ned[j])) {
            if(!j) return true;
            --cur; --j;
        }
        pos += skip[toLowerAscii(hay[pos])];
    }
    return false;
}


// ═══════════════════════════════════════════════════════════════════════════════
// Signature patterns — AND-logic: ALL required[] strings must be found
// XOR key (0x5A) obfuscates strings so scanner binary never flags itself!
// ═══════════════════════════════════════════════════════════════════════════════
struct Pattern {
    std::string              name;
    Sev                      sev;
    std::vector<std::string> required;   // ALL must match (AND logic)
    std::string              fileType;   // "" = any, "PE" = PE only, "TEXT" = text only, "ELF" = ELF
    bool                     noCase = false;
};

static std::vector<Pattern> PATTERNS;

static std::string xd(const char* enc, size_t len, uint8_t key = 0x5A) {
    std::string s;
    s.reserve(len);
    for(size_t i = 0; i < len; ++i) s += (char)((uint8_t)enc[i] ^ key);
    return s;
}

static void initPatterns() {
    PATTERNS.clear();

    static const char e_0_0[] = "\x02\x6f\x15\x7b\x0a\x7f\x1a\x1b\x0a\x01\x6e\x06\x0a\x00\x02\x6f\x6e\x72\x0a\x04\x73\x6d\x19\x19\x73\x6d\x27\x7e\x1f\x13\x19\x1b\x08\x77\x09\x0e\x1b\x14\x1e\x1b\x08\x1e\x77\x1b\x14\x0e\x13\x0c\x13\x08\x0f\x09\x77\x0e\x1f\x09\x0e\x77\x1c\x13\x16\x1f\x7b\x7e\x12\x71\x12\x70"; // "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    PATTERNS.push_back({"EICAR-Test-File", Sev::Info, {xd(e_0_0, 68)}, "", false});

    static const char e_1_0[] = "\x0d\x14\x39\x28\x23\x1a\x68\x35\x36\x6d"; // "WNcry@2ol7"
    static const char e_1_1[] = "\x74\x2d\x34\x28\x23"; // ".wnry"
    PATTERNS.push_back({"Ransom.WannaCry", Sev::Critical, {xd(e_1_0, 10), xd(e_1_1, 5)}, "PE", false});

    static const char e_2_0[] = "\x17\x13\x08\x1b\x13"; // "MIRAI"
    static const char e_2_1[] = "\x75\x2a\x28\x35\x39\x75\x34\x3f\x2e\x75\x2e\x39\x2a"; // "/proc/net/tcp"
    PATTERNS.push_back({"Trojan.Mirai.Bot", Sev::Critical, {xd(e_2_0, 5), xd(e_2_1, 13)}, "ELF", false});

    static const char e_3_0[] = "\x08\x3f\x29\x2e\x35\x28\x3f\x77\x17\x23\x77\x1c\x33\x36\x3f\x29\x74\x2e\x22\x2e"; // "Restore-My-Files.txt"
    static const char e_3_1[] = "\x1b\x36\x36\x7a\x23\x35\x2f\x28\x7a\x3c\x33\x36\x3f\x29\x7a\x3b\x28\x3f\x7a\x3f\x34\x39\x28\x23\x2a\x2e\x3f\x3e\x7a\x38\x23\x7a\x16\x35\x39\x31\x18\x33\x2e"; // "All your files are encrypted by LockBit"
    PATTERNS.push_back({"Ransom.LockBit", Sev::Critical, {xd(e_3_0, 20), xd(e_3_1, 39)}, "", true});

    static const char e_4_0[] = "\x05\x16\x35\x39\x31\x23\x05\x28\x3f\x39\x35\x2c\x3f\x28\x05\x33\x34\x29\x2e\x28\x2f\x39\x2e\x33\x35\x34\x29\x74\x2e\x22\x2e"; // "_Locky_recover_instructions.txt"
    PATTERNS.push_back({"Ransom.Locky", Sev::Critical, {xd(e_4_0, 31)}, "", true});

    static const char e_5_0[] = "\x1f\x37\x35\x2e\x3f\x3e\x17\x2f\x2e\x3f\x22"; // "EmotedMutex"
    PATTERNS.push_back({"Trojan.Emotet", Sev::Critical, {xd(e_5_0, 11)}, "PE", false});

    static const char e_6_0[] = "\x1b\x3d\x3f\x34\x2e\x0e\x3f\x29\x36\x3b"; // "AgentTesla"
    static const char e_6_1[] = "\x31\x3f\x23\x36\x35\x3d"; // "keylog"
    PATTERNS.push_back({"Trojan.AgentTesla", Sev::Critical, {xd(e_6_0, 10), xd(e_6_1, 6)}, "PE", false});

    static const char e_7_0[] = "\x1d\x32\x6a\x29\x2e"; // "Gh0st"
    static const char e_7_1[] = "\x3d\x32\x6a\x29\x2e\x74\x33\x34\x33"; // "gh0st.ini"
    PATTERNS.push_back({"Trojan.Gh0stRAT", Sev::Critical, {xd(e_7_0, 5), xd(e_7_1, 9)}, "PE", false});

    static const char e_8_0[] = "\x1d\x3f\x2e\x1b\x29\x23\x34\x39\x11\x3f\x23\x09\x2e\x3b\x2e\x3f"; // "GetAsyncKeyState"
    static const char e_8_1[] = "\x1d\x3f\x2e\x11\x3f\x23\x38\x35\x3b\x28\x3e\x09\x2e\x3b\x2e\x3f"; // "GetKeyboardState"
    PATTERNS.push_back({"Spyware.PowerShell.Keylogger", Sev::High, {xd(e_8_0, 16), xd(e_8_1, 16)}, "PS1", true});

    static const char e_9_0[] = "\x1d\x3f\x2e\x1b\x29\x23\x34\x39\x11\x3f\x23\x09\x2e\x3b\x2e\x3f"; // "GetAsyncKeyState"
    static const char e_9_1[] = "\x17\x3b\x2a\x0c\x33\x28\x2e\x2f\x3b\x36\x11\x3f\x23"; // "MapVirtualKey"
    PATTERNS.push_back({"Spyware.PowerShell.Keylogger", Sev::High, {xd(e_9_0, 16), xd(e_9_1, 13)}, "PS1", true});

    static const char e_10_0[] = "\x1d\x3f\x2e\x1b\x29\x23\x34\x39\x11\x3f\x23\x09\x2e\x3b\x2e\x3f"; // "GetAsyncKeyState"
    static const char e_10_1[] = "\x0e\x35\x0f\x34\x33\x39\x35\x3e\x3f"; // "ToUnicode"
    PATTERNS.push_back({"Spyware.PowerShell.Keylogger", Sev::High, {xd(e_10_0, 16), xd(e_10_1, 9)}, "PS1", true});

    static const char e_11_0[] = "\x09\x3f\x2e\x0d\x33\x34\x3e\x35\x2d\x29\x12\x35\x35\x31\x1f\x22"; // "SetWindowsHookEx"
    static const char e_11_1[] = "\x0d\x12\x05\x11\x1f\x03\x18\x15\x1b\x08\x1e"; // "WH_KEYBOARD"
    PATTERNS.push_back({"Spyware.Hook.Keylogger", Sev::High, {xd(e_11_0, 16), xd(e_11_1, 11)}, "PE", false});

    static const char e_12_0[] = "\x14\x3f\x2e\x74\x09\x35\x39\x31\x3f\x2e\x29\x74\x0e\x19\x0a\x19\x36\x33\x3f\x34\x2e"; // "Net.Sockets.TCPClient"
    static const char e_12_1[] = "\x1d\x3f\x2e\x09\x2e\x28\x3f\x3b\x37"; // "GetStream"
    PATTERNS.push_back({"Backdoor.PowerShell.ReverseShell", Sev::High, {xd(e_12_0, 21), xd(e_12_1, 9)}, "PS1", true});

    static const char e_13_0[] = "\x38\x3b\x29\x32\x7a\x77\x33"; // "bash -i"
    static const char e_13_1[] = "\x75\x3e\x3f\x2c\x75\x2e\x39\x2a\x75"; // "/dev/tcp/"
    PATTERNS.push_back({"Backdoor.RevShell.Bash", Sev::High, {xd(e_13_0, 7), xd(e_13_1, 9)}, "SH", true});

    static const char e_14_0[] = "\x34\x39\x7a\x77\x3f\x7a\x75\x38\x33\x34\x75"; // "nc -e /bin/"
    PATTERNS.push_back({"Backdoor.NetCat.Shell", Sev::High, {xd(e_14_0, 11)}, "SH", true});

    static const char e_15_0[] = "\x34\x39\x3b\x2e\x7a\x77\x3f\x7a\x75\x38\x33\x34\x75"; // "ncat -e /bin/"
    PATTERNS.push_back({"Backdoor.NetCat.Shell", Sev::High, {xd(e_15_0, 13)}, "SH", true});

    static const char e_16_0[] = "\x29\x35\x39\x3b\x2e"; // "socat"
    static const char e_16_1[] = "\x3f\x22\x3f\x39\x60"; // "exec:"
    static const char e_16_2[] = "\x2e\x39\x2a\x60"; // "tcp:"
    PATTERNS.push_back({"Backdoor.Socat.Shell", Sev::High, {xd(e_16_0, 5), xd(e_16_1, 5), xd(e_16_2, 4)}, "SH", true});

    static const char e_17_0[] = "\x29\x35\x39\x31\x3f\x2e\x74\x29\x35\x39\x31\x3f\x2e"; // "socket.socket"
    static const char e_17_1[] = "\x35\x29\x74\x3e\x2f\x2a\x68"; // "os.dup2"
    static const char e_17_2[] = "\x29\x2f\x38\x2a\x28\x35\x39\x3f\x29\x29\x74\x39\x3b\x36\x36"; // "subprocess.call"
    PATTERNS.push_back({"Backdoor.Python.ReverseShell", Sev::High, {xd(e_17_0, 13), xd(e_17_1, 7), xd(e_17_2, 15)}, "PY", true});

    static const char e_18_0[] = "\x1b\x37\x29\x33\x0f\x2e\x33\x36\x29"; // "AmsiUtils"
    static const char e_18_1[] = "\x3b\x37\x29\x33\x13\x34\x33\x2e\x1c\x3b\x33\x36\x3f\x3e"; // "amsiInitFailed"
    PATTERNS.push_back({"HackTool.PowerShell.AmsiBypass", Sev::High, {xd(e_18_0, 9), xd(e_18_1, 14)}, "PS1", true});

    static const char e_19_0[] = "\x1b\x37\x29\x33\x09\x39\x3b\x34\x18\x2f\x3c\x3c\x3f\x28"; // "AmsiScanBuffer"
    static const char e_19_1[] = "\x0c\x33\x28\x2e\x2f\x3b\x36\x0a\x28\x35\x2e\x3f\x39\x2e"; // "VirtualProtect"
    PATTERNS.push_back({"HackTool.PowerShell.AmsiBypass", Sev::High, {xd(e_19_0, 14), xd(e_19_1, 14)}, "PS1", true});

    static const char e_20_0[] = "\x09\x3f\x2e\x77\x17\x2a\x0a\x28\x3f\x3c\x3f\x28\x3f\x34\x39\x3f"; // "Set-MpPreference"
    static const char e_20_1[] = "\x1e\x33\x29\x3b\x38\x36\x3f\x08\x3f\x3b\x36\x2e\x33\x37\x3f\x17\x35\x34\x33\x2e\x35\x28\x33\x34\x3d"; // "DisableRealtimeMonitoring"
    PATTERNS.push_back({"Trojan.PowerShell.DisableDefender", Sev::High, {xd(e_20_0, 16), xd(e_20_1, 25)}, "SCRIPT", true});

    static const char e_21_0[] = "\x09\x3f\x2e\x77\x17\x2a\x0a\x28\x3f\x3c\x3f\x28\x3f\x34\x39\x3f"; // "Set-MpPreference"
    static const char e_21_1[] = "\x1e\x33\x29\x3b\x38\x36\x3f\x18\x3f\x32\x3b\x2c\x33\x35\x28\x17\x35\x34\x33\x2e\x35\x28\x33\x34\x3d"; // "DisableBehaviorMonitoring"
    PATTERNS.push_back({"Trojan.PowerShell.DisableDefender", Sev::High, {xd(e_21_0, 16), xd(e_21_1, 25)}, "SCRIPT", true});

    static const char e_22_0[] = "\x1b\x3e\x3e\x77\x17\x2a\x0a\x28\x3f\x3c\x3f\x28\x3f\x34\x39\x3f"; // "Add-MpPreference"
    static const char e_22_1[] = "\x1f\x22\x39\x36\x2f\x29\x33\x35\x34\x0a\x3b\x2e\x32"; // "ExclusionPath"
    PATTERNS.push_back({"Trojan.PowerShell.DisableDefender", Sev::High, {xd(e_22_0, 16), xd(e_22_1, 13)}, "SCRIPT", true});

    static const char e_23_0[] = "\x77\x1f\x34\x39\x35\x3e\x3f\x3e\x19\x35\x37\x37\x3b\x34\x3e"; // "-EncodedCommand"
    static const char e_23_1[] = "\x1c\x28\x35\x37\x18\x3b\x29\x3f\x6c\x6e\x09\x2e\x28\x33\x34\x3d"; // "FromBase64String"
    PATTERNS.push_back({"Script.PowerShell.DownloadCradle", Sev::High, {xd(e_23_0, 15), xd(e_23_1, 16)}, "PS1", true});

    static const char e_24_0[] = "\x1e\x35\x2d\x34\x36\x35\x3b\x3e\x09\x2e\x28\x33\x34\x3d"; // "DownloadString"
    static const char e_24_1[] = "\x13\x34\x2c\x35\x31\x3f\x77\x1f\x22\x2a\x28\x3f\x29\x29\x33\x35\x34"; // "Invoke-Expression"
    PATTERNS.push_back({"Script.PowerShell.DownloadExecute", Sev::High, {xd(e_24_0, 14), xd(e_24_1, 17)}, "PS1", true});

    static const char e_25_0[] = "\x1e\x35\x2d\x34\x36\x35\x3b\x3e\x09\x2e\x28\x33\x34\x3d"; // "DownloadString"
    static const char e_25_1[] = "\x13\x1f\x02"; // "IEX"
    PATTERNS.push_back({"Script.PowerShell.DownloadExecute", Sev::High, {xd(e_25_0, 14), xd(e_25_1, 3)}, "PS1", true});

    static const char e_26_0[] = "\x13\x34\x2c\x35\x31\x3f\x77\x17\x33\x37\x33\x31\x3b\x2e\x20"; // "Invoke-Mimikatz"
    PATTERNS.push_back({"HackTool.PowerShell.Mimikatz", Sev::Critical, {xd(e_26_0, 15)}, "PS1", true});

    static const char e_27_0[] = "\x29\x3f\x31\x2f\x28\x36\x29\x3b\x60\x60\x36\x35\x3d\x35\x34\x2a\x3b\x29\x29\x2d\x35\x28\x3e\x29"; // "sekurlsa::logonpasswords"
    PATTERNS.push_back({"HackTool.PowerShell.Mimikatz", Sev::Critical, {xd(e_27_0, 24)}, "PS1", true});

    static const char e_28_0[] = "\x39\x35\x37\x29\x2c\x39\x29\x74\x3e\x36\x36"; // "comsvcs.dll"
    static const char e_28_1[] = "\x17\x33\x34\x33\x1e\x2f\x37\x2a"; // "MiniDump"
    PATTERNS.push_back({"HackTool.Script.LsassDump", Sev::Critical, {xd(e_28_0, 11), xd(e_28_1, 8)}, "SCRIPT", true});

    static const char e_29_0[] = "\x34\x2e\x3e\x29\x2f\x2e\x33\x36"; // "ntdsutil"
    static const char e_29_1[] = "\x33\x3c\x37"; // "ifm"
    PATTERNS.push_back({"HackTool.Script.LsassDump", Sev::Critical, {xd(e_29_0, 8), xd(e_29_1, 3)}, "SCRIPT", true});

    static const char e_30_0[] = "\x14\x3f\x2e\x74\x17\x3b\x33\x36\x74\x09\x37\x2e\x2a\x19\x36\x33\x3f\x34\x2e"; // "Net.Mail.SmtpClient"
    static const char e_30_1[] = "\x29\x37\x2e\x2a\x74"; // "smtp."
    static const char e_30_2[] = "\x14\x3f\x2e\x2d\x35\x28\x31\x19\x28\x3f\x3e\x3f\x34\x2e\x33\x3b\x36"; // "NetworkCredential"
    PATTERNS.push_back({"Spyware.Script.SmtpExfiltration", Sev::High, {xd(e_30_0, 19), xd(e_30_1, 5), xd(e_30_2, 17)}, "PS1", true});

    static const char e_31_0[] = "\x14\x3f\x2e\x74\x17\x3b\x33\x36\x74\x09\x37\x2e\x2a\x19\x36\x33\x3f\x34\x2e"; // "Net.Mail.SmtpClient"
    static const char e_31_1[] = "\x6f\x62\x6d"; // "587"
    static const char e_31_2[] = "\x19\x28\x3f\x3e\x3f\x34\x2e\x33\x3b\x36\x29"; // "Credentials"
    PATTERNS.push_back({"Spyware.Script.SmtpExfiltration", Sev::High, {xd(e_31_0, 19), xd(e_31_1, 3), xd(e_31_2, 11)}, "PS1", true});

    static const char e_32_0[] = "\x19\x1e\x15\x74\x17\x3f\x29\x29\x3b\x3d\x3f"; // "CDO.Message"
    static const char e_32_1[] = "\x39\x3e\x35\x75\x39\x35\x34\x3c\x33\x3d\x2f\x28\x3b\x2e\x33\x35\x34"; // "cdo/configuration"
    static const char e_32_2[] = "\x29\x37\x2e\x2a\x29\x3f\x28\x2c\x3f\x28"; // "smtpserver"
    PATTERNS.push_back({"Spyware.Script.SmtpExfiltration", Sev::High, {xd(e_32_0, 11), xd(e_32_1, 17), xd(e_32_2, 10)}, "VBS", true});

    static const char e_33_0[] = "\x29\x37\x2e\x2a\x36\x33\x38\x74\x09\x17\x0e\x0a"; // "smtplib.SMTP"
    static const char e_33_1[] = "\x29\x3f\x34\x3e\x37\x3b\x33\x36"; // "sendmail"
    static const char e_33_2[] = "\x2a\x3b\x29\x29\x2d\x35\x28\x3e"; // "password"
    PATTERNS.push_back({"Spyware.Script.SmtpExfiltration", Sev::High, {xd(e_33_0, 12), xd(e_33_1, 8), xd(e_33_2, 8)}, "PY", true});

    static const char e_34_0[] = "\x3b\x2a\x33\x75\x2d\x3f\x38\x32\x35\x35\x31\x29\x75"; // "api/webhooks/"
    static const char e_34_1[] = "\x13\x34\x2c\x35\x31\x3f\x77\x08\x3f\x29\x2e\x17\x3f\x2e\x32\x35\x3e"; // "Invoke-RestMethod"
    PATTERNS.push_back({"Spyware.Script.DiscordWebhook", Sev::High, {xd(e_34_0, 13), xd(e_34_1, 17)}, "SCRIPT", true});

    static const char e_35_0[] = "\x3b\x2a\x33\x75\x2d\x3f\x38\x32\x35\x35\x31\x29\x75"; // "api/webhooks/"
    static const char e_35_1[] = "\x13\x34\x2c\x35\x31\x3f\x77\x0d\x3f\x38\x08\x3f\x2b\x2f\x3f\x29\x2e"; // "Invoke-WebRequest"
    PATTERNS.push_back({"Spyware.Script.DiscordWebhook", Sev::High, {xd(e_35_0, 13), xd(e_35_1, 17)}, "SCRIPT", true});

    static const char e_36_0[] = "\x3b\x2a\x33\x75\x2d\x3f\x38\x32\x35\x35\x31\x29\x75"; // "api/webhooks/"
    static const char e_36_1[] = "\x0f\x2a\x36\x35\x3b\x3e\x1c\x33\x36\x3f"; // "UploadFile"
    PATTERNS.push_back({"Spyware.Script.DiscordWebhook", Sev::High, {xd(e_36_0, 13), xd(e_36_1, 10)}, "SCRIPT", true});

    static const char e_37_0[] = "\x3b\x2a\x33\x74\x2e\x3f\x36\x3f\x3d\x28\x3b\x37\x74\x35\x28\x3d\x75\x38\x35\x2e"; // "api.telegram.org/bot"
    static const char e_37_1[] = "\x29\x3f\x34\x3e\x1e\x35\x39\x2f\x37\x3f\x34\x2e"; // "sendDocument"
    PATTERNS.push_back({"Spyware.Script.TelegramExfil", Sev::High, {xd(e_37_0, 20), xd(e_37_1, 12)}, "SCRIPT", true});

    static const char e_38_0[] = "\x3b\x2a\x33\x74\x2e\x3f\x36\x3f\x3d\x28\x3b\x37\x74\x35\x28\x3d\x75\x38\x35\x2e"; // "api.telegram.org/bot"
    static const char e_38_1[] = "\x29\x3f\x34\x3e\x17\x3f\x29\x29\x3b\x3d\x3f"; // "sendMessage"
    PATTERNS.push_back({"Spyware.Script.TelegramExfil", Sev::High, {xd(e_38_0, 20), xd(e_38_1, 11)}, "SCRIPT", true});

    static const char e_39_0[] = "\x38\x33\x2e\x29\x3b\x3e\x37\x33\x34"; // "bitsadmin"
    static const char e_39_1[] = "\x75\x2e\x28\x3b\x34\x29\x3c\x3f\x28"; // "/transfer"
    static const char e_39_2[] = "\x32\x2e\x2e\x2a"; // "http"
    PATTERNS.push_back({"Trojan.Script.BitsadminDownload", Sev::High, {xd(e_39_0, 9), xd(e_39_1, 9), xd(e_39_2, 4)}, "BAT", true});

    static const char e_40_0[] = "\x38\x33\x2e\x29\x3b\x3e\x37\x33\x34"; // "bitsadmin"
    static const char e_40_1[] = "\x75\x3b\x3e\x3e\x3c\x33\x36\x3f"; // "/addfile"
    static const char e_40_2[] = "\x32\x2e\x2e\x2a"; // "http"
    PATTERNS.push_back({"Trojan.Script.BitsadminDownload", Sev::High, {xd(e_40_0, 9), xd(e_40_1, 8), xd(e_40_2, 4)}, "BAT", true});

    static const char e_41_0[] = "\x39\x3f\x28\x2e\x2f\x2e\x33\x36\x7a\x77\x3e\x3f\x39\x35\x3e\x3f\x7a"; // "certutil -decode "
    PATTERNS.push_back({"Trojan.Script.CertutilDecode", Sev::High, {xd(e_41_0, 17)}, "BAT", true});

    static const char e_42_0[] = "\x39\x3f\x28\x2e\x2f\x2e\x33\x36\x74\x3f\x22\x3f\x7a\x77\x3e\x3f\x39\x35\x3e\x3f"; // "certutil.exe -decode"
    PATTERNS.push_back({"Trojan.Script.CertutilDecode", Sev::High, {xd(e_42_0, 20)}, "BAT", true});

    static const char e_43_0[] = "\x39\x3f\x28\x2e\x2f\x2e\x33\x36"; // "certutil"
    static const char e_43_1[] = "\x77\x2f\x28\x36\x39\x3b\x39\x32\x3f"; // "-urlcache"
    static const char e_43_2[] = "\x32\x2e\x2e\x2a"; // "http"
    PATTERNS.push_back({"Script.Batch.CertutilDownload", Sev::High, {xd(e_43_0, 8), xd(e_43_1, 9), xd(e_43_2, 4)}, "BAT", true});

    static const char e_44_0[] = "\x39\x3f\x28\x2e\x2f\x2e\x33\x36"; // "certutil"
    static const char e_44_1[] = "\x77\x29\x2a\x36\x33\x2e"; // "-split"
    static const char e_44_2[] = "\x32\x2e\x2e\x2a"; // "http"
    PATTERNS.push_back({"Script.Batch.CertutilDownload", Sev::High, {xd(e_44_0, 8), xd(e_44_1, 6), xd(e_44_2, 4)}, "BAT", true});

    static const char e_45_0[] = "\x3c\x2e\x2a\x7a\x77\x29\x60"; // "ftp -s:"
    static const char e_45_1[] = "\x35\x2a\x3f\x34\x7a"; // "open "
    static const char e_45_2[] = "\x3d\x3f\x2e\x7a"; // "get "
    PATTERNS.push_back({"Trojan.Script.FtpScriptDownload", Sev::High, {xd(e_45_0, 7), xd(e_45_1, 5), xd(e_45_2, 4)}, "BAT", true});

    static const char e_46_0[] = "\x29\x29\x32\x7a"; // "ssh "
    static const char e_46_1[] = "\x77\x08\x7a"; // "-R "
    static const char e_46_2[] = "\x77\x14"; // "-N"
    PATTERNS.push_back({"Backdoor.SSH.ReverseTunnel", Sev::High, {xd(e_46_0, 4), xd(e_46_1, 3), xd(e_46_2, 2)}, "SCRIPT", true});

    static const char e_47_0[] = "\x2a\x36\x33\x34\x31"; // "plink"
    static const char e_47_1[] = "\x77\x08\x7a"; // "-R "
    static const char e_47_2[] = "\x77\x2a\x2d"; // "-pw"
    PATTERNS.push_back({"Backdoor.SSH.ReverseTunnel", Sev::High, {xd(e_47_0, 5), xd(e_47_1, 3), xd(e_47_2, 3)}, "SCRIPT", true});

    static const char e_48_0[] = "\x29\x29\x32\x7a"; // "ssh "
    static const char e_48_1[] = "\x77\x1e\x7a"; // "-D "
    static const char e_48_2[] = "\x77\x3c"; // "-f"
    PATTERNS.push_back({"Backdoor.SSH.DynamicSocks", Sev::High, {xd(e_48_0, 4), xd(e_48_1, 3), xd(e_48_2, 2)}, "SH", true});

    static const char e_49_0[] = "\x3b\x2f\x2e\x32\x35\x28\x33\x20\x3f\x3e\x05\x31\x3f\x23\x29"; // "authorized_keys"
    static const char e_49_1[] = "\x29\x29\x32\x77\x28\x29\x3b"; // "ssh-rsa"
    static const char e_49_2[] = "\x3f\x39\x32\x35\x7a"; // "echo "
    PATTERNS.push_back({"Backdoor.SSH.AuthorizedKeysInjection", Sev::High, {xd(e_49_0, 15), xd(e_49_1, 7), xd(e_49_2, 5)}, "SH", true});

    static const char e_50_0[] = "\x3b\x2f\x2e\x32\x35\x28\x33\x20\x3f\x3e\x05\x31\x3f\x23\x29"; // "authorized_keys"
    static const char e_50_1[] = "\x29\x29\x32\x77\x3f\x3e\x68\x6f\x6f\x6b\x63"; // "ssh-ed25519"
    PATTERNS.push_back({"Backdoor.SSH.AuthorizedKeysInjection", Sev::High, {xd(e_50_0, 15), xd(e_50_1, 11)}, "SH", true});

    static const char e_51_0[] = "\x74\x29\x29\x32"; // ".ssh"
    static const char e_51_1[] = "\x33\x3e\x05\x28\x29\x3b"; // "id_rsa"
    static const char e_51_2[] = "\x1d\x3f\x2e\x77\x19\x35\x34\x2e\x3f\x34\x2e"; // "Get-Content"
    PATTERNS.push_back({"HackTool.SSH.KeyHarvesting", Sev::High, {xd(e_51_0, 4), xd(e_51_1, 6), xd(e_51_2, 11)}, "SCRIPT", true});

    static const char e_52_0[] = "\x74\x29\x29\x32"; // ".ssh"
    static const char e_52_1[] = "\x33\x3e\x05\x3f\x3e\x68\x6f\x6f\x6b\x63"; // "id_ed25519"
    static const char e_52_2[] = "\x39\x3b\x2e\x7a"; // "cat "
    PATTERNS.push_back({"HackTool.SSH.KeyHarvesting", Sev::High, {xd(e_52_0, 4), xd(e_52_1, 10), xd(e_52_2, 4)}, "SCRIPT", true});

    static const char e_53_0[] = "\x16\x35\x3d\x33\x34\x7a\x1e\x3b\x2e\x3b"; // "Login Data"
    static const char e_53_1[] = "\x19\x28\x23\x2a\x2e\x0f\x34\x2a\x28\x35\x2e\x3f\x39\x2e\x1e\x3b\x2e\x3b"; // "CryptUnprotectData"
    PATTERNS.push_back({"Spyware.Script.BrowserStealer", Sev::High, {xd(e_53_0, 10), xd(e_53_1, 18)}, "SCRIPT", true});

    static const char e_54_0[] = "\x1d\x35\x35\x3d\x36\x3f\x06\x19\x32\x28\x35\x37\x3f\x06\x0f\x29\x3f\x28\x7a\x1e\x3b\x2e\x3b"; // "Google\Chrome\User Data"
    static const char e_54_1[] = "\x16\x35\x3d\x33\x34\x7a\x1e\x3b\x2e\x3b"; // "Login Data"
    PATTERNS.push_back({"Spyware.Script.BrowserStealer", Sev::High, {xd(e_54_0, 23), xd(e_54_1, 10)}, "SCRIPT", true});

    static const char e_55_0[] = "\x1b\x2a\x2a\x1e\x3b\x2e\x3b\x06\x16\x35\x39\x3b\x36\x06\x1d\x35\x35\x3d\x36\x3f\x06\x19\x32\x28\x35\x37\x3f"; // "AppData\Local\Google\Chrome"
    static const char e_55_1[] = "\x19\x35\x35\x31\x33\x3f\x29"; // "Cookies"
    PATTERNS.push_back({"Spyware.Script.BrowserStealer", Sev::High, {xd(e_55_0, 27), xd(e_55_1, 7)}, "SCRIPT", true});

    static const char e_56_0[] = "\x09\x23\x29\x2e\x3f\x37\x74\x1e\x28\x3b\x2d\x33\x34\x3d\x74\x1d\x28\x3b\x2a\x32\x33\x39\x29"; // "System.Drawing.Graphics"
    static const char e_56_1[] = "\x19\x35\x2a\x23\x1c\x28\x35\x37\x09\x39\x28\x3f\x3f\x34"; // "CopyFromScreen"
    PATTERNS.push_back({"Spyware.Script.ScreenCapture", Sev::High, {xd(e_56_0, 23), xd(e_56_1, 14)}, "PS1", true});

    static const char e_57_0[] = "\x09\x3f\x2e\x77\x19\x36\x33\x2a\x38\x35\x3b\x28\x3e"; // "Set-Clipboard"
    static const char e_57_1[] = "\x6a\x22"; // "0x"
    static const char e_57_2[] = "\x28\x3f\x3d\x3f\x22"; // "regex"
    PATTERNS.push_back({"Spyware.Script.ClipboardHijacker", Sev::High, {xd(e_57_0, 13), xd(e_57_1, 2), xd(e_57_2, 5)}, "PS1", true});

    static const char e_58_0[] = "\x2a\x23\x2a\x3f\x28\x39\x36\x33\x2a"; // "pyperclip"
    static const char e_58_1[] = "\x6a\x22"; // "0x"
    static const char e_58_2[] = "\x28\x3f\x74\x29\x2f\x38"; // "re.sub"
    PATTERNS.push_back({"Spyware.Script.ClipboardHijacker", Sev::High, {xd(e_58_0, 9), xd(e_58_1, 2), xd(e_58_2, 6)}, "PY", true});

    static const char e_59_0[] = "\x28\x3f\x3d\x29\x2c\x28\x69\x68"; // "regsvr32"
    static const char e_59_1[] = "\x29\x39\x28\x35\x38\x30\x74\x3e\x36\x36"; // "scrobj.dll"
    static const char e_59_2[] = "\x75\x33\x60\x32\x2e\x2e\x2a"; // "/i:http"
    PATTERNS.push_back({"Exploit.LOLBin.Regsvr32", Sev::High, {xd(e_59_0, 8), xd(e_59_1, 10), xd(e_59_2, 7)}, "BAT", true});

    static const char e_60_0[] = "\x28\x3f\x3d\x29\x2c\x28\x69\x68"; // "regsvr32"
    static const char e_60_1[] = "\x29\x39\x28\x35\x38\x30\x74\x3e\x36\x36"; // "scrobj.dll"
    static const char e_60_2[] = "\x75\x29\x7a\x75\x2f"; // "/s /u"
    PATTERNS.push_back({"Exploit.LOLBin.Regsvr32", Sev::High, {xd(e_60_0, 8), xd(e_60_1, 10), xd(e_60_2, 5)}, "BAT", true});

    static const char e_61_0[] = "\x28\x2f\x34\x3e\x36\x36\x69\x68"; // "rundll32"
    static const char e_61_1[] = "\x08\x2f\x34\x12\x0e\x17\x16\x1b\x2a\x2a\x36\x33\x39\x3b\x2e\x33\x35\x34"; // "RunHTMLApplication"
    static const char e_61_2[] = "\x30\x3b\x2c\x3b\x29\x39\x28\x33\x2a\x2e\x60"; // "javascript:"
    PATTERNS.push_back({"Exploit.LOLBin.Rundll32", Sev::High, {xd(e_61_0, 8), xd(e_61_1, 18), xd(e_61_2, 11)}, "BAT", true});

    static const char e_62_0[] = "\x37\x29\x32\x2e\x3b"; // "mshta"
    static const char e_62_1[] = "\x32\x2e\x2e\x2a\x60\x75\x75"; // "http://"
    PATTERNS.push_back({"Exploit.LOLBin.Mshta", Sev::High, {xd(e_62_0, 5), xd(e_62_1, 7)}, "BAT", true});

    static const char e_63_0[] = "\x37\x29\x32\x2e\x3b"; // "mshta"
    static const char e_63_1[] = "\x32\x2e\x2e\x2a\x29\x60\x75\x75"; // "https://"
    PATTERNS.push_back({"Exploit.LOLBin.Mshta", Sev::High, {xd(e_63_0, 5), xd(e_63_1, 8)}, "BAT", true});

    static const char e_64_0[] = "\x37\x29\x32\x2e\x3b"; // "mshta"
    static const char e_64_1[] = "\x2c\x38\x29\x39\x28\x33\x2a\x2e\x60"; // "vbscript:"
    PATTERNS.push_back({"Exploit.LOLBin.Mshta", Sev::High, {xd(e_64_0, 5), xd(e_64_1, 9)}, "BAT", true});

    static const char e_65_0[] = "\x19\x2f\x28\x28\x3f\x34\x2e\x0c\x3f\x28\x29\x33\x35\x34\x06\x08\x2f\x34"; // "CurrentVersion\Run"
    static const char e_65_1[] = "\x28\x3f\x3d\x7a\x3b\x3e\x3e"; // "reg add"
    PATTERNS.push_back({"Trojan.Script.RegRunPersistence", Sev::High, {xd(e_65_0, 18), xd(e_65_1, 7)}, "SCRIPT", true});

    static const char e_66_0[] = "\x19\x2f\x28\x28\x3f\x34\x2e\x0c\x3f\x28\x29\x33\x35\x34\x06\x08\x2f\x34"; // "CurrentVersion\Run"
    static const char e_66_1[] = "\x14\x3f\x2d\x77\x13\x2e\x3f\x37\x0a\x28\x35\x2a\x3f\x28\x2e\x23"; // "New-ItemProperty"
    PATTERNS.push_back({"Trojan.Script.RegRunPersistence", Sev::High, {xd(e_66_0, 18), xd(e_66_1, 16)}, "SCRIPT", true});

    static const char e_67_0[] = "\x29\x39\x32\x2e\x3b\x29\x31\x29"; // "schtasks"
    static const char e_67_1[] = "\x75\x39\x28\x3f\x3b\x2e\x3f"; // "/create"
    static const char e_67_2[] = "\x75\x29\x39\x7a\x35\x34\x36\x35\x3d\x35\x34"; // "/sc onlogon"
    PATTERNS.push_back({"Trojan.Script.SchtasksPersistence", Sev::High, {xd(e_67_0, 8), xd(e_67_1, 7), xd(e_67_2, 11)}, "BAT", true});

    static const char e_68_0[] = "\x29\x39\x32\x2e\x3b\x29\x31\x29"; // "schtasks"
    static const char e_68_1[] = "\x75\x39\x28\x3f\x3b\x2e\x3f"; // "/create"
    static const char e_68_2[] = "\x75\x29\x39\x7a\x35\x34\x29\x2e\x3b\x28\x2e"; // "/sc onstart"
    PATTERNS.push_back({"Trojan.Script.SchtasksPersistence", Sev::High, {xd(e_68_0, 8), xd(e_68_1, 7), xd(e_68_2, 11)}, "BAT", true});

    static const char e_69_0[] = "\x29\x39\x32\x2e\x3b\x29\x31\x29"; // "schtasks"
    static const char e_69_1[] = "\x75\x39\x28\x3f\x3b\x2e\x3f"; // "/create"
    static const char e_69_2[] = "\x75\x28\x2f\x7a\x29\x23\x29\x2e\x3f\x37"; // "/ru system"
    PATTERNS.push_back({"Trojan.Script.SchtasksPersistence", Sev::High, {xd(e_69_0, 8), xd(e_69_1, 7), xd(e_69_2, 10)}, "BAT", true});

    static const char e_70_0[] = "\x19\x35\x37\x37\x3b\x34\x3e\x16\x33\x34\x3f\x1f\x2c\x3f\x34\x2e\x19\x35\x34\x29\x2f\x37\x3f\x28"; // "CommandLineEventConsumer"
    static const char e_70_1[] = "\x05\x05\x1c\x33\x36\x2e\x3f\x28\x0e\x35\x19\x35\x34\x29\x2f\x37\x3f\x28\x18\x33\x34\x3e\x33\x34\x3d"; // "__FilterToConsumerBinding"
    PATTERNS.push_back({"Trojan.PowerShell.WmiPersistence", Sev::High, {xd(e_70_0, 24), xd(e_70_1, 25)}, "PS1", true});

    static const char e_71_0[] = "\x2c\x29\x29\x3b\x3e\x37\x33\x34"; // "vssadmin"
    static const char e_71_1[] = "\x3e\x3f\x36\x3f\x2e\x3f\x7a\x29\x32\x3b\x3e\x35\x2d\x29"; // "delete shadows"
    PATTERNS.push_back({"Ransom.Script.ShadowDelete", Sev::High, {xd(e_71_0, 8), xd(e_71_1, 14)}, "BAT", true});

    static const char e_72_0[] = "\x2d\x37\x33\x39"; // "wmic"
    static const char e_72_1[] = "\x29\x32\x3b\x3e\x35\x2d\x39\x35\x2a\x23\x7a\x3e\x3f\x36\x3f\x2e\x3f"; // "shadowcopy delete"
    PATTERNS.push_back({"Ransom.Script.ShadowDelete", Sev::High, {xd(e_72_0, 4), xd(e_72_1, 17)}, "BAT", true});

    static const char e_73_0[] = "\x38\x39\x3e\x3f\x3e\x33\x2e"; // "bcdedit"
    static const char e_73_1[] = "\x28\x3f\x39\x35\x2c\x3f\x28\x23\x3f\x34\x3b\x38\x36\x3f\x3e\x7a\x34\x35"; // "recoveryenabled no"
    PATTERNS.push_back({"Ransom.Script.RecoveryDisable", Sev::High, {xd(e_73_0, 7), xd(e_73_1, 18)}, "BAT", true});

    static const char e_74_0[] = "\x1e\x33\x29\x3b\x38\x36\x3f\x1b\x34\x2e\x33\x09\x2a\x23\x2d\x3b\x28\x3f"; // "DisableAntiSpyware"
    static const char e_74_1[] = "\x0d\x33\x34\x3e\x35\x2d\x29\x7a\x1e\x3f\x3c\x3f\x34\x3e\x3f\x28"; // "Windows Defender"
    PATTERNS.push_back({"Trojan.Batch.DisableAV", Sev::High, {xd(e_74_0, 18), xd(e_74_1, 16)}, "BAT", true});

    static const char e_75_0[] = "\x34\x3f\x2e\x29\x32\x7a\x3b\x3e\x2c\x3c\x33\x28\x3f\x2d\x3b\x36\x36"; // "netsh advfirewall"
    static const char e_75_1[] = "\x29\x2e\x3b\x2e\x3f\x7a\x35\x3c\x3c"; // "state off"
    PATTERNS.push_back({"Trojan.Batch.DisableFirewall", Sev::High, {xd(e_75_0, 17), xd(e_75_1, 9)}, "BAT", true});

    static const char e_76_0[] = "\x7f\x6a\x26\x7f\x6a"; // "%0|%0"
    PATTERNS.push_back({"Trojan.Batch.ForkBomb", Sev::Medium, {xd(e_76_0, 5)}, "BAT", false});

    static const char e_77_0[] = "\x02\x17\x16\x12\x0e\x0e\x0a"; // "XMLHTTP"
    static const char e_77_1[] = "\x1b\x1e\x15\x1e\x18\x74\x09\x2e\x28\x3f\x3b\x37"; // "ADODB.Stream"
    static const char e_77_2[] = "\x09\x3b\x2c\x3f\x0e\x35\x1c\x33\x36\x3f"; // "SaveToFile"
    PATTERNS.push_back({"Script.VBS.XMLHTTPDropper", Sev::High, {xd(e_77_0, 7), xd(e_77_1, 12), xd(e_77_2, 10)}, "VBS", true});

    static const char e_78_0[] = "\x0d\x09\x39\x28\x33\x2a\x2e\x74\x09\x32\x3f\x36\x36"; // "WScript.Shell"
    static const char e_78_1[] = "\x74\x08\x2f\x34\x72"; // ".Run("
    PATTERNS.push_back({"Script.VBS.ShellExec", Sev::High, {xd(e_78_0, 13), xd(e_78_1, 5)}, "VBS", true});

    static const char e_79_0[] = "\x66\x32\x2e\x3b\x60\x3b\x2a\x2a\x36\x33\x39\x3b\x2e\x33\x35\x34"; // "<hta:application"
    static const char e_79_1[] = "\x0d\x09\x39\x28\x33\x2a\x2e\x74\x09\x32\x3f\x36\x36"; // "WScript.Shell"
    PATTERNS.push_back({"Script.HTA.Dropper", Sev::High, {xd(e_79_0, 16), xd(e_79_1, 13)}, "HTA", true});

    static const char e_80_0[] = "\x66\x32\x2e\x3b\x60\x3b\x2a\x2a\x36\x33\x39\x3b\x2e\x33\x35\x34"; // "<hta:application"
    static const char e_80_1[] = "\x2a\x35\x2d\x3f\x28\x29\x32\x3f\x36\x36"; // "powershell"
    PATTERNS.push_back({"Script.HTA.Dropper", Sev::High, {xd(e_80_0, 16), xd(e_80_1, 10)}, "HTA", true});

    static const char e_81_0[] = "\x1b\x39\x2e\x33\x2c\x3f\x02\x15\x38\x30\x3f\x39\x2e"; // "ActiveXObject"
    static const char e_81_1[] = "\x0d\x09\x39\x28\x33\x2a\x2e\x74\x09\x32\x3f\x36\x36"; // "WScript.Shell"
    static const char e_81_2[] = "\x2a\x35\x2d\x3f\x28\x29\x32\x3f\x36\x36"; // "powershell"
    PATTERNS.push_back({"Script.JS.WScriptDropper", Sev::High, {xd(e_81_0, 13), xd(e_81_1, 13), xd(e_81_2, 10)}, "JS", true});

    static const char e_82_0[] = "\x29\x2e\x28\x3b\x2e\x2f\x37\x71\x2e\x39\x2a\x60\x75\x75"; // "stratum+tcp://"
    PATTERNS.push_back({"Trojan.Script.Cryptominer", Sev::High, {xd(e_82_0, 14)}, "SH", true});

    static const char e_83_0[] = "\x29\x2e\x28\x3b\x2e\x2f\x37\x71\x29\x29\x36\x60\x75\x75"; // "stratum+ssl://"
    PATTERNS.push_back({"Trojan.Script.Cryptominer", Sev::High, {xd(e_83_0, 14)}, "SH", true});

    static const char e_84_0[] = "\x22\x37\x28\x33\x3d"; // "xmrig"
    PATTERNS.push_back({"Trojan.Script.Cryptominer", Sev::High, {xd(e_84_0, 5)}, "SH", true});

    static const char e_85_0[] = "\x60\x72\x73\x21\x7a\x60\x26\x60\x7c\x7a\x27\x61\x60"; // ":(){ :|:& };:"
    PATTERNS.push_back({"Trojan.Bash.ForkBomb", Sev::Medium, {xd(e_85_0, 13)}, "SH", false});

    static const char e_86_0[] = "\x28\x37\x7a\x77\x28\x3c\x7a\x77\x77\x34\x35\x77\x2a\x28\x3f\x29\x3f\x28\x2c\x3f\x77\x28\x35\x35\x2e"; // "rm -rf --no-preserve-root"
    PATTERNS.push_back({"Trojan.Bash.Wiper", Sev::Critical, {xd(e_86_0, 25)}, "SH", true});

    static const char e_87_0[] = "\x28\x37\x7a\x77\x28\x3c\x7a\x75\x70"; // "rm -rf /*"
    PATTERNS.push_back({"Trojan.Bash.Wiper", Sev::Critical, {xd(e_87_0, 9)}, "SH", true});

}

// ═══════════════════════════════════════════════════════════════════════════════
static const uint8_t METER_X86[] = {0xFC,0xE8,0x82,0x00,0x00,0x00,0x60,0x89,0xE5,0x31};
static const uint8_t METER_X64[] = {0xFC,0x48,0x83,0xE4,0xF0,0xE8,0xC8,0x00,0x00,0x00};


// ═══════════════════════════════════════════════════════════════════════════════
// Scanner self-exclusion & trusted path filters
// ═══════════════════════════════════════════════════════════════════════════════
static bool isSelfOrIgnored(const fs::path& p) {
    std::string fn = p.filename().string();
    // Don't scan the scanner binary or its own code files
    if(fn == "scantouch" || fn == "scantouch.exe" || fn == "scantouch.cpp")
        return true;
    return false;
}

static bool isTrustedPath(const fs::path& p) {
    std::string s = p.string();
    for(char& c : s) if(c == '\\') c = '/';

    static const char* trusted[] = {
        "/Windows/",
        "/windows/",
        "/Program Files/",
        "/Program Files (x86)/",
        "/Microsoft/Windows Defender/",
        "/All Users/Microsoft/Windows Defender/",
        nullptr
    };
    for(int i = 0; trusted[i]; ++i)
        if(s.find(trusted[i]) != std::string::npos) return true;
    return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// File type by magic bytes
// ═══════════════════════════════════════════════════════════════════════════════
static std::string fileType(const uint8_t* d, size_t n) {
    if(!d || n < 4) return "UNKNOWN";
    if(d[0]=='M' && d[1]=='Z') return "PE";
    if(d[0]==0x7F && d[1]=='E' && d[2]=='L' && d[3]=='F')
        return n > 4 && d[4]==2 ? "ELF64" : "ELF32";
    uint32_t m = 0; memcpy(&m, d, 4);
    if(m==0xFEEDFACE || m==0xCEFAEDFE) return "MACHO";
    if(m==0xFEEDFACF || m==0xCFFAEDFE) return "MACHO";
    if(m==0xBEBAFECA || m==0xCAFEBABE) return "MACHO";
    if(d[0]=='P' && d[1]=='K') return "ZIP";
    if(d[0]==0x1F && d[1]==0x8B) return "GZIP";
    if(d[0]=='R' && d[1]=='a' && d[2]=='r') return "RAR";
    if(d[0]=='7' && d[1]=='z') return "7ZIP";
    if(d[0]=='B' && d[1]=='Z' && d[2]=='h') return "BZIP2";
    if(n >= 5 && memcmp(d, "%PDF-", 5) == 0) return "PDF";
    bool ok = true;
    for(size_t i = 0; i < std::min(n, size_t(512)); i++)
        if((d[i] > 0 && d[i] < 9) || (d[i] > 13 && d[i] < 32)) { ok=false; break; }
    return ok ? "TEXT" : "BINARY";
}

static bool isTargetMatch(const std::string& target, const fs::path& p, const std::string& ftype) {
    if (target.empty()) return true;
    if (target == "PE") return ftype == "PE";
    if (target == "ELF") return ftype == "ELF32" || ftype == "ELF64";

    std::string ext = p.extension().string();
    for (char& c : ext) if (c >= 'A' && c <= 'Z') c += 32;

    if (target == "PS1") {
        return ext == ".ps1" || ext == ".psm1" || ext == ".psd1";
    }
    if (target == "BAT") {
        return ext == ".bat" || ext == ".cmd";
    }
    if (target == "VBS") {
        return ext == ".vbs" || ext == ".vbe" || ext == ".wsf" || ext == ".wsc";
    }
    if (target == "HTA") {
        return ext == ".hta";
    }
    if (target == "SH") {
        return ext == ".sh" || ext == ".bash" || ext == ".zsh" || (ftype == "TEXT" && ext.empty());
    }
    if (target == "PY") {
        return ext == ".py" || ext == ".pyw";
    }
    if (target == "JS") {
        return ext == ".js" || ext == ".jse";
    }
    if (target == "SCRIPT") {
        return ext == ".ps1" || ext == ".psm1" || ext == ".bat" || ext == ".cmd" ||
               ext == ".vbs" || ext == ".vbe" || ext == ".wsf" || ext == ".hta" ||
               ext == ".sh" || ext == ".bash" || ext == ".py" || ext == ".pyw" ||
               (ftype == "TEXT" && ext.empty());
    }
    return false;
}

static bool isPE(const std::string& ft)    { return ft == "PE"; }
static bool isELF(const std::string& ft)   { return ft == "ELF32" || ft == "ELF64"; }
static bool isText(const std::string& ft)  { return ft == "TEXT"; }
static bool isBinary(const std::string& ft){ return !isText(ft); }

// ═══════════════════════════════════════════════════════════════════════════════
// Heuristics — tuned to avoid false positives on legitimate software
// ═══════════════════════════════════════════════════════════════════════════════
struct HScore {
    bool hasPackerSection  = false;
    bool hasHighEntropy    = false;
    bool hasMinimalImports = false;

    int compute() const {
        int s = 0;
        // Known packer section name (UPX0, ASPack, etc.)
        if(hasPackerSection)  s += 45;
        // Very high entropy (> 7.6) combined with packer
        if(hasHighEntropy)    s += 35;
        // Only LoadLibrary/GetProcAddress present (typical packer stager)
        if(hasMinimalImports) s += 20;
        return s;
    }

    std::string flags() const {
        std::string f;
        if(hasPackerSection)  f += " packer-section";
        if(hasHighEntropy)    f += " high-entropy";
        if(hasMinimalImports) f += " minimal-imports";
        return f.empty() ? "none" : f;
    }
};

static HScore heuristic(const uint8_t* d, size_t n, const std::string& ft, double ent) {
    HScore s;
    // Heuristics run only on PE binaries (Windows executables)
    if(!isPE(ft) || n < 512) return s;

    // Check for known packer section headers
    static const char* packers[] = {
        "UPX0","UPX1","UPX2",".aspack",".petite",".themida",
        ".vmp0",".vmp1","MPRESS1","MPRESS2",nullptr
    };
    for(int i = 0; packers[i]; i++) {
        if(strFind(d, n, packers[i])) {
            s.hasPackerSection = true;
            break;
        }
    }

    // High entropy (> 7.6 indicates packed or heavily encrypted code)
    if(ent > 7.6) s.hasHighEntropy = true;

    // Minimal imports check: only dynamic loader APIs, no normal OS imports
    if(s.hasPackerSection) {
        bool hasLoad = strFind(d,n,"LoadLibraryA") || strFind(d,n,"LoadLibraryW");
        bool hasGPA  = strFind(d,n,"GetProcAddress");
        bool hasStd  = strFind(d,n,"CreateFileW") || strFind(d,n,"CreateWindowExW") || strFind(d,n,"RegOpenKeyExW");
        if(hasLoad && hasGPA && !hasStd) s.hasMinimalImports = true;
    }

    return s;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Core scan logic
// ═══════════════════════════════════════════════════════════════════════════════
struct ScanOpts {
    bool recursive   = true;
    bool useHeur     = true;
    bool verbose     = false;
    bool jsonOut     = false;
    bool skipTrusted = true;
    int  threads     = 0;
    size_t maxSize   = 0;
    std::vector<std::string> exclExt;
    std::vector<std::string> exclPath;
};

static FileResult scanBuf(const uint8_t* data, size_t sz,
                          const fs::path& path, const ScanOpts& o) {
    FileResult r; r.path = path; r.size = (int64_t)sz;
    if(!data || !sz) return r;

    r.sha256 = sha256Buf(data, sz);
    r.md5    = md5Buf(data, sz);
    r.ftype  = fileType(data, sz);
    r.ent    = entropy(data, sz);

    // 1. Exact hash lookup (0% false positives)
    {
        auto it = KNOWN.find(r.sha256);
        if(it == KNOWN.end()) it = KNOWN.find(r.md5);
        if(it != KNOWN.end()) {
            Threat t; t.name = it->second.first; t.sev = it->second.second;
            t.details = "Exact hash match";
            r.threats.push_back(t);
            return r; // Hash match is definitive
        }
    }

    // 2. Binary shellcode stubs (binary files only)
    if(isBinary(r.ftype)) {
        if(bmhFind(data, sz, METER_X86, sizeof(METER_X86)))
            r.threats.push_back({"Trojan.Meterpreter.x86", "Raw shellcode bytes", Sev::Critical, 0});
        if(bmhFind(data, sz, METER_X64, sizeof(METER_X64)))
            r.threats.push_back({"Trojan.CobaltStrike.Beacon", "Raw shellcode bytes", Sev::Critical, 0});
    }

    // 3. AND-logic signature patterns
    for(const auto& p : PATTERNS) {
        if(!isTargetMatch(p.fileType, path, r.ftype)) continue;

        if(p.required.empty()) continue;
        bool allFound = true;
        for(const auto& req : p.required) {
            bool found = false;
            if(p.noCase) {
                found = bmhFindNoCase(data, sz,
                            reinterpret_cast<const uint8_t*>(req.data()),
                            req.size());
            } else {
                found = bmhFind(data, sz,
                            reinterpret_cast<const uint8_t*>(req.data()),
                            req.size());
            }
            if(!found) { allFound = false; break; }
        }
        if(!allFound) continue;

        bool dup = false;
        for(const auto& e : r.threats) if(e.name == p.name) { dup = true; break; }
        if(!dup) {
            Threat t; t.name = p.name; t.sev = p.sev;
            t.details = "Signature match (" + std::to_string(p.required.size()) + " indicators)";
            r.threats.push_back(t);
        }
    }

    // 4. Heuristics (only on PE binaries, high threshold >= 80)
    if(o.useHeur) {
        auto hs = heuristic(data, sz, r.ftype, r.ent);
        int sc = hs.compute();
        if(sc >= 80) {
            Threat t;
            t.name    = sc >= 90 ? "Heuristic.SuspiciousPacker" : "Packer.Generic.Packed";
            t.sev     = sc >= 90 ? Sev::High : Sev::Medium;
            t.score   = sc;
            t.details = "Score:" + std::to_string(sc) + "/100 Flags:" + hs.flags();
            r.threats.push_back(t);
        }
    }

    return r;
}

static FileResult scanFile(const fs::path& path, const ScanOpts& o) {
    FileResult r; r.path = path;

    // Skip scanner binary and source code
    if(isSelfOrIgnored(path)) return r;

    // Skip Windows Defender and trusted system directories
    if(o.skipTrusted && isTrustedPath(path)) return r;

    // Skip user-specified exclude paths
    std::string ps = path.string();
    for(const auto& ep : o.exclPath)
        if(ps.find(ep) != std::string::npos) return r;

    std::error_code ec;
    auto sz = fs::file_size(path, ec);
    if(ec || !sz) return r;
    if(o.maxSize > 0 && sz > o.maxSize) return r;
    r.size = (int64_t)sz;

    std::ifstream f(path, std::ios::binary);
    if(!f) return r;
    std::vector<uint8_t> buf(sz);
    f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)sz);
    buf.resize((size_t)f.gcount());
    return scanBuf(buf.data(), buf.size(), path, o);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Output helpers
// ═══════════════════════════════════════════════════════════════════════════════
static std::string jStr(const std::string& s){
    std::string o="\"";for(char c:s){
        if(c=='"')o+="\\\"";else if(c=='\\')o+="\\\\";
        else if(c=='\n')o+="\\n";else o+=c;}return o+"\"";}

static std::mutex gMtx;

static void printResult(const FileResult& r,bool json,bool verbose){
    if(!r.isThreat()&&!verbose)return;
    std::lock_guard<std::mutex> lk(gMtx);

    if(json){
        std::cout<<"{\n  \"file\":"<<jStr(r.path.string())<<",\n"
                 <<"  \"sha256\":"<<jStr(r.sha256)<<",\n"
                 <<"  \"md5\":"<<jStr(r.md5)<<",\n"
                 <<"  \"type\":"<<jStr(r.ftype)<<",\n"
                 <<"  \"size\":"<<r.size<<",\n"
                 <<"  \"entropy\":"<<std::fixed<<std::setprecision(2)<<r.ent<<",\n"
                 <<"  \"threats\":[\n";
        for(size_t i=0;i<r.threats.size();i++){
            const auto& t=r.threats[i];
            std::cout<<"    {\"name\":"<<jStr(t.name)<<",\"severity\":"<<jStr(sevStr(t.sev))
                     <<",\"score\":"<<t.score<<",\"details\":"<<jStr(t.details)<<"}";
            if(i+1<r.threats.size())std::cout<<",";std::cout<<"\n";}
        std::cout<<"  ]\n},\n";return;}

    if(r.isThreat()){
        Sev worst=Sev::Clean;for(const auto& t:r.threats)if(t.sev>worst)worst=t.sev;
        const char* tag=worst>=Sev::High?"[MALWARE]":"[SUSPECT]";
        const char* col=worst>=Sev::High?Color::red():Color::yellow();
        std::cout<<col<<tag<<Color::reset()<<" "<<r.path.string()<<"\n";
        for(const auto& t:r.threats){
            std::cout<<"        \u2192 "<<Color::bold()<<t.name<<Color::reset()
                     <<" ["<<sevStr(t.sev)<<"]"
                     <<(t.score>0?" score="+std::to_string(t.score):"")<<"\n";
            if(!t.details.empty())std::cout<<"          "<<t.details<<"\n";
        }
    } else if(verbose){
        std::cout<<Color::green()<<"[CLEAN]"<<Color::reset()<<" "<<r.path.string()
                 <<" (ent:"<<std::fixed<<std::setprecision(1)<<r.ent<<")\n";
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main scan runner
// ═══════════════════════════════════════════════════════════════════════════════
static int doScan(const std::string& target,const ScanOpts& o){
    auto t0=std::chrono::steady_clock::now();
    fs::path tp(target);std::error_code ec;auto st=fs::status(tp,ec);
    if(ec){std::cerr<<"Error: cannot access '"<<target<<"': "<<ec.message()<<"\n";return 2;}

    std::vector<fs::path> files;
    if(fs::is_regular_file(st)){
        files.push_back(tp);
    } else if(fs::is_directory(st)){
        if(o.recursive){
            // Manual recursive walk — avoids Windows junction-point crash.
            // recursive_directory_iterator stops on the first junction it hits
            // (e.g. C:\Users\Default User, C:\Users\All Users).
            // directory_iterator + explicit recursion is reliable on all OS.
            std::function<void(const fs::path&, int)> walk =
                [&](const fs::path& dir, int depth){
                    if(depth > 32) return;  // guard against circular junctions
                    std::error_code ec;
                    fs::directory_iterator it(dir,
                        fs::directory_options::skip_permission_denied, ec);
                    for(; !ec && it != fs::directory_iterator(); it.increment(ec)){
                        std::error_code entEc;
                        // Read symlink status to detect Windows junctions
                        auto lstat = it->symlink_status(entEc);
                        if(entEc) continue;
                        // Skip symlinks and junction points — don't follow them
                        if(fs::is_symlink(lstat)) continue;

                        auto fstat = it->status(entEc);
                        if(entEc) continue;
                        if(fs::is_regular_file(fstat)){
                            files.push_back(it->path());
                        } else if(fs::is_directory(fstat)){
                            walk(it->path(), depth + 1);
                        }
                    }
                };
            walk(tp, 0);
        } else {
            std::error_code itEc;
            for(auto& e : fs::directory_iterator(tp,
                    fs::directory_options::skip_permission_denied, itEc)){
                std::error_code entEc;
                if(e.is_regular_file(entEc)) files.push_back(e.path());
            }
        }
    }

    uint64_t total=(uint64_t)files.size();
    std::atomic<uint64_t> scanned{0},clean{0},infected{0},suspicious{0},skipped{0},bytes{0};

    if(!o.jsonOut)
        std::cout<<Color::cyan()<<"[*]"<<Color::reset()<<" Scanning "<<total<<" files in "<<target<<"\n\n";
    else
        std::cout<<"[\n";

    std::atomic<size_t> nextIdx{0};
    auto worker=[&](){
        while(true){
            size_t idx=nextIdx.fetch_add(1);if(idx>=files.size())break;
            const auto& fp=files[idx];
            std::string ext=fp.extension().string();
            bool excl=false;for(const auto& e:o.exclExt)if(ext==e){excl=true;break;}
            if(excl){++skipped;continue;}
            if(!o.jsonOut&&!o.verbose){
                static std::mutex pm;std::lock_guard<std::mutex> lk(pm);
                uint64_t done=scanned.load();
                if(total>100&&done%100==0)
                    std::cout<<"\r  Progress: "<<done<<"/"<<total<<"  "
                             <<fp.filename().string().substr(0,50)<<"          "<<std::flush;
            }
            auto r=scanFile(fp,o);++scanned;
            bytes+=(uint64_t)std::max(int64_t(0),r.size);
            if(r.isThreat()){
                Sev w=Sev::Clean;for(const auto& t:r.threats)if(t.sev>w)w=t.sev;
                if(w>=Sev::High)++infected;else++suspicious;
            } else ++clean;
            printResult(r,o.jsonOut,o.verbose);
        }
    };

    unsigned nth=o.threads>0?(unsigned)o.threads:std::thread::hardware_concurrency();
    if(!nth)nth=4;nth=std::min(nth,(unsigned)std::max(size_t(1),files.size()));
    std::vector<std::thread> threads;
    for(unsigned i=0;i<nth;i++)threads.emplace_back(worker);
    for(auto& t:threads)t.join();

    double elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();

    if(o.jsonOut){std::cout<<"{}]\n";return (infected+suspicious)>0?1:0;}

    std::cout<<"\n\n";
    uint64_t threats=infected+suspicious;
    std::cout<<Color::bold()
        <<"  \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n"
        <<"  \u2551            SCAN SUMMARY                  \u2551\n"
        <<"  \u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n"
        <<Color::reset();
    std::cout<<"  \u2551  Files scanned:   "<<std::setw(8)<<scanned.load()<<"                  \u2551\n"
             <<"  \u2551  Clean:           "<<Color::green()<<std::setw(8)<<clean.load()<<Color::reset()<<"                  \u2551\n"
             <<"  \u2551  Infected:        "<<Color::red()<<std::setw(8)<<infected.load()<<Color::reset()<<"                  \u2551\n"
             <<"  \u2551  Suspicious:      "<<Color::yellow()<<std::setw(8)<<suspicious.load()<<Color::reset()<<"                  \u2551\n"
             <<"  \u2551  Skipped:         "<<std::setw(8)<<skipped.load()<<"                  \u2551\n"
             <<"  \u2551  Data scanned:    "<<std::setw(6)<<(bytes.load()/(1024*1024))<<" MB                \u2551\n"
             <<"  \u2551  Time:            "<<std::fixed<<std::setprecision(1)<<std::setw(6)<<elapsed<<" sec               \u2551\n";
    std::cout<<Color::bold()
        <<"  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n\n"
        <<Color::reset();
    const char* rc=threats>0?Color::red():Color::green();
    std::cout<<"  "<<rc<<Color::bold()
             <<(threats>0?"\u26a0 THREATS DETECTED: "+std::to_string(threats):"\u2713 System is CLEAN")
             <<Color::reset()<<"\n\n";
    return threats>0?1:0;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════════
int main(int argc,char** argv){
    winConsoleInit();          // Windows: enable UTF-8 + ANSI colors
    Color::enabled=IS_TTY();

    initPatterns();

    if(argc<2){
        std::cout<<"ScanTouch Antivirus v1.0.0 — Zero-Dependency Scanner\n\n"
                 <<"Usage:\n"
                 <<"  scantouch scan <path> [options]\n"
                 <<"  scantouch version\n\n"
                 <<"Options:\n"
                 <<"  --no-recursive      Don't recurse subdirectories\n"
                 <<"  --no-heuristic      Disable heuristic engine\n"
                 <<"  --json              JSON output\n"
                 <<"  --verbose           Show clean files too\n"
                 <<"  --no-skip-trusted   Scan Windows Defender and system directories\n"
                 <<"  --threads N         Parallel threads (default: auto)\n"
                 <<"  --max-size MB       Skip files > N MB\n"
                 <<"  --exclude-ext .ext  Skip extension (repeatable)\n"
                 <<"  --exclude-path sub  Skip path substring (repeatable)\n\n"
                 <<"Examples:\n"
                 <<"  scantouch scan /tmp\n"
                 <<"  scantouch scan C:\\Users\n"
                 <<"  scantouch scan C:\\Users --json\n"
                 <<"  scantouch scan /home --max-size 100 --exclude-ext .log\n\n";
        return 0;
    }

    std::string cmd=argv[1];

    if(cmd=="version"){
        std::cout<<"ScanTouch Antivirus v1.0.0\n"
                 <<"Mode:     standalone, zero external dependencies\n"
                 <<"Compiled: "<<__DATE__<<" "<<__TIME__<<"\n"
                 <<"Patterns: "<<PATTERNS.size()<<" multi-indicator signatures\n"
                 <<"Hashes:   "<<KNOWN.size()<<" known-bad entries\n";
        return 0;
    }

    if(cmd=="scan"){
        if(argc<3){std::cerr<<"Error: scan requires a path.\nUsage: scantouch scan <path>\n";return 2;}
        std::string target=argv[2];
        ScanOpts o;
        for(int i=3;i<argc;i++){
            std::string a=argv[i];
            if(a=="--no-recursive")        o.recursive=false;
            else if(a=="--no-heuristic")   o.useHeur=false;
            else if(a=="--json")           o.jsonOut=true;
            else if(a=="--verbose")        o.verbose=true;
            else if(a=="--no-skip-trusted")o.skipTrusted=false;
            else if(a=="--threads"   && i+1<argc) o.threads=std::stoi(argv[++i]);
            else if(a=="--max-size"  && i+1<argc) o.maxSize=(size_t)std::stoul(argv[++i])*1024*1024;
            else if(a=="--exclude-ext"  && i+1<argc) o.exclExt.push_back(argv[++i]);
            else if(a=="--exclude-path" && i+1<argc) o.exclPath.push_back(argv[++i]);
        }

        if(!o.jsonOut){
            std::cout<<Color::bold()
                     <<"\n  \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n"
                     <<"  \u2551   ScanTouch Antivirus v1.0.0         \u2551\n"
                     <<"  \u2551   Zero-Dependency Standalone Scanner  \u2551\n"
                     <<"  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n\n"
                     <<Color::reset();
        }
        return doScan(target,o);
    }

    std::cerr<<"Unknown command '"<<cmd<<"'. Run 'scantouch' for help.\n";
    return 2;
}
