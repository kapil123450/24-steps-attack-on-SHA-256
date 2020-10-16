#include<bits/stdc++.h>
#include <stdint.h>
#include <string>
#include <string.h>
#include<fstream>

using namespace std ;
const int wordsize = 4;//byte
typedef unsigned char Byte;
#  define rotl(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#  define rotr(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define hd(x) (x>=97?10+x-97:x-'0')
/*
  This class computes SHA256 message digests.
*/
class SHA256 {
public:
	/* This type needs to be at least 32 bits, unsigned */
	typedef unsigned int UInt32; 
	/* This is the type of the data you're processing */
	typedef unsigned char Byte;
	
	/* This is the data type of a message digest. */
	class digest {
	public:
		enum {size=32}; // bytes in a message digest
		SHA256::Byte data[size]; // binary digest data
		
		// Equality.  This is useful for "if (cur==target)" tests.
		bool operator==(const digest &other) const {
			for (int i=0;i<size;i++)
				if (data[i]!=other.data[i])
					return false;
			return true;
		}
		
		// Less-than.  This is mostly useful for std::map<SHA256::digest, ...>
		bool operator<(const digest &other) const {
			for (int i=0;i<size;i++)
				if (data[i]<other.data[i])
					return true;
				else if (data[i]>other.data[i])
					return false;
			return false;
		}
		
		// Convert digest to an ASCII string of hex digits (for printouts)
		std::string toHex() const;
	};
	
/* External Interface */
	SHA256(); // constructor.  Sets up initial state.

	// Add raw binary message data to our hash. 
	//  You can call this repeatedly to add as much data as you want.
	void add(const void *data, size_t size);
	
	// Finish this message and extract the digest. 
	// Resets so you can add the next message, if desired.
	SHA256::digest finish(void);
	
	~SHA256(); // destructor.  Clears out state and buffered data.
	
/* Internal Interface (public, for debug's sake) */
	// This is the internal state of the hash.
	UInt32 state[8];
	
	// This is how many message bytes we've seen so far.
	size_t count;
	
	// This buffers up to a whole block of data
	Byte buffer[64];
	
	
	// Reset to initial values.
	void init();
	
	// Process the finished block of data in "buffer"
	void block();
};


/* This is the *really* easy version: given a string as input, return the digest as output. 
     std::cout<<"SHA-256: "<<SHA256_digest(someString).toHex()<<"\n";
*/
inline SHA256::digest SHA256_digest(const std::string &src) {
	SHA256 hash;
    cout<<src.length()<<endl;
	hash.add(&src[0],src.length());
	return hash.finish();
}


/************** Bit twiddling and round operations for SHA256 *************/

/* Define bit rotate operations.  These work like:
UInt32 ror(UInt32 value,UInt32 bitcount)
*/
#ifdef _MSC_VER /* Windows bit rotate from standard library */
#  include <stdlib.h>
#  define rol(x, n) _rotl((x), (n))
#  define ror(x, n) _rotr((x), (n))
#else /* portable (Linux, Mac, etc) bit rotate */
#  define rol(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#  define ror(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#endif

/* These are the round keys, one per round. */
static const SHA256::UInt32 K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* This sets up the Sha256 initial state, at the start of a message. */
void SHA256::init()
{
  state[0] = 0x6a09e667;
  state[1] = 0xbb67ae85;
  state[2] = 0x3c6ef372;
  state[3] = 0xa54ff53a;
  state[4] = 0x510e527f;
  state[5] = 0x9b05688c;
  state[6] = 0x1f83d9ab;
  state[7] = 0x5be0cd19;
  count = 0;
}
SHA256::SHA256() {
  init();
}

unsigned int ROUND_COUNT=24; // HACK

/* This adds another block of data to our current state.
   This is our main transforming/mixing function. */
void SHA256::block()
{
  unsigned i;

  UInt32 KWi[64]; // Per-round key + work data

// First part of W is just the incoming message data */
#define s0(x) (ror(x, 7) ^ ror(x,18) ^ (x >> 3))
#define s1(x) (ror(x,17) ^ ror(x,19) ^ (x >> 10))
  UInt32 W[16]; // Work buffer: 0-15 are straight from the data
  for (i = 0; i < 16; i++) {
     W[i]=
      ((UInt32)(buffer[i * 4    ]) << 24) +
      ((UInt32)(buffer[i * 4 + 1]) << 16) +
      ((UInt32)(buffer[i * 4 + 2]) <<  8) +
      ((UInt32)(buffer[i * 4 + 3])); // big-endian 32-bit load
     KWi[i]=W[i]+K[i];
  }

// The rest of W is a scrambled copy of the original data
  for (;i<ROUND_COUNT;i++) 
  {
	W[i&15] += s1(W[(i-2)&15]) + W[(i-7)&15] + s0(W[(i-15)&15]);
	KWi[i] = W[i&15]+K[i];
  }

  UInt32 a,b,c,d,e,f,g,h; /* local copies of state, for performance */
  a=state[0]; b=state[1];  c=state[2];  d=state[3]; 
  e=state[4]; f=state[5];  g=state[6];  h=state[7]; 

// This is the main data transform loop
  for (i = 0; i < ROUND_COUNT; i++) { 
	// SHA-256 round function:
	// Mixing
	h += (ror(e,6)^ror(e,11)^ror(e,25)) + (g^(e&(f^g))) + KWi[i]; // "Ch"
	d += h;
	h += (ror(a,2)^ror(a,13)^ror(a,22)) + ((a&b)|(c&(a|b))); // "Maj"
	
	// Cyclic shift of variables:
	UInt32 old_h=h; 
	h=g; g=f; f=e; e=d; d=c; c=b; b=a; a=old_h;
  }

// Add result back into state array
  state[0]+=a; state[1]+=b;  state[2]+=c;  state[3]+=d; 
  state[4]+=e; state[5]+=f;  state[6]+=g;  state[7]+=h; 
  
  /* Wipe temporary variables, for paranoia */
  memset(W, 0, sizeof(W));
  memset(KWi, 0, sizeof(KWi));
}


// Add raw binary message data to our hash. 
void SHA256::add(const void *data, size_t size)
{
  const Byte *dataptr=(const Byte *)data;
  UInt32 curBufferPos = (UInt32)count & 0x3F; /* location within last block */
  while (size > 0)
  {
    buffer[curBufferPos++] = *dataptr++; // copy next byte of data
    count++; // message got longer
    size--; // user data got shorter
    if (curBufferPos == 64) // we have one whole block finished
    {
      curBufferPos = 0;
      block();
    }
  }
}

/* End Sha256 processing, and write out message digest. */
SHA256::digest SHA256::finish(void)
{
  size_t lenInBits = (count << 3); // i.e., times 8 bits per byte
  UInt32 curBufferPos = (UInt32)count & 0x3F; // 0x3f is mask to wrap around to buffer size
  unsigned i;
  buffer[curBufferPos++] = 0x80; // standard specifies "add a one bit...
  while (curBufferPos != (64 - 8)) // ...then pad with zeros to end of block"
  {
    curBufferPos &= 0x3F;
    if (curBufferPos == 0) 
      block();
    buffer[curBufferPos++] = 0; // zero out rest of block
  }
  
  // Finally, add message length, in bits, as big-endian 64 bit number
  for (i = 0; i < 8; i++)
  {
    buffer[curBufferPos++] = (Byte)(lenInBits >> 56);
    lenInBits <<= 8;
  }
  
  block(); // transform last block (including length)

  // Copy state out as big-endian integers.
  SHA256::digest output;
  for (i = 0; i < 8; i++)
  {
    output.data[i*4+0] = (Byte)(state[i] >> 24);
    output.data[i*4+1] = (Byte)(state[i] >> 16);
    output.data[i*4+2] = (Byte)(state[i] >> 8);
    output.data[i*4+3] = (Byte)(state[i]);
  }
  
  init(); // reset for next trip around
  
  return output;
}

SHA256::~SHA256()
{
	// To keep from leaving any sensitive data lying around, zero out our buffers.
	memset(state,0,sizeof(state));
	count=0;
	memset(buffer,0,sizeof(buffer)); 
}

std::string SHA256::digest::toHex() const
{
	std::string ret="";
	for (int i=0;i<size;i++) {
		const char *hexdigit="0123456789abcdef";
		ret+=hexdigit[(data[i]>>4)&0xf]; // high 4 bits
		ret+=hexdigit[(data[i]   )&0xf]; // low 4 bits
	}
	return ret;
}

typedef unsigned int UInt32; 
UInt32 state[8];
const UInt32 k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

UInt32 a[24],b[24],c[24],d[24],e[24],f[24],g[24],h[24];

UInt32 w1[24];
UInt32 w2[24];
UInt32 del1 = 0x00006000,del2 = 0xff006001,u=1,valpha = 0x32b308b2,vlembda = 0x051f9f7f,vgamma = 0x98e3923b,vmu=0xfbe05f81 , vbeta = ~(0x32b308b2);

UInt32 randomWord(){
    const UInt32 range_from  = 0;
    const UInt32 range_to    = 1<<32-1;
    std::random_device                  rand_dev;
    std::mt19937                        generator(rand_dev());
    std::uniform_int_distribution<UInt32>  distr(range_from, range_to);
    return distr(generator);

}
string string_to_hex(UInt32 x){
    static const char hex_digits[] = "0123456789ABCDEF";

    stack<char> output ;
    
    
    int i=0 ;
    while(i<4)
    {
        Byte c = x&255;
        
        output.push(hex_digits[c&15]);
        output.push(hex_digits[c>>4]);
        x = x>>8;
        i++;
    }
    
    string op2;
    op2.resize(8);
    while(!output.empty()){
        op2.push_back(output.top());
        output.pop();
    }
    
    return op2;
}
//s17s19r10
UInt32 sigma1(UInt32 wrd)
{
    return rotr(wrd,17)^rotr(wrd,19)^(wrd>>10);
}
UInt32 sigma0(UInt32 wrd)
{
    return rotr(wrd,7)^rotr(wrd,18)^(wrd>>3);
}

UInt32 summ0(UInt32 wrd)
{
    return rotr(wrd,2)^rotr(wrd,13)^rotr(wrd,22);
}

UInt32 summ1(UInt32 wrd)
{
    return rotr(wrd,6)^rotr(wrd,11)^rotr(wrd,25);
}

UInt32 fif(UInt32 x, UInt32 y, UInt32 z)
{
    return (x&y)^((~x)&z);
}

UInt32 fmaj(UInt32 x, UInt32 y, UInt32 z){
    return (x&y)^(y&z)^(z&x);
}

UInt32 W_to_set_register_A(int step, UInt32 da ){
    return da-(summ0(a[step-1])+fmaj(a[step-1],b[step-1],c[step-1])+summ1(e[step-1])+fif(e[step-1],f[step-1],g[step-1])+h[step-1]+k[step]);
}
UInt32 W_to_set_register_E(int step, UInt32 de ){
    return de-(d[step-1]+summ1(e[step-1])+fif(e[step-1],f[step-1],g[step-1])+h[step-1]+k[step]);
}

void hashEvaluation(int step){
    if(step==0)
    {
        a[step] = summ0(state[0])+fmaj(state[0],state[1],state[2])+summ1(state[4])+fif(state[4],state[5],state[6])+state[7]+k[step]+w1[step];
        b[step] = state[0];
        c[step] = state[1];
        d[step] = state[2];
        e[step] = state[3]+summ1(state[4])+fif(state[4],state[5],state[6])+state[7]+k[step]+w1[step];
        f[step] = state[4];
        g[step] = state[5];
        h[step] = state[6];
    }
    else
    {
        a[step] = summ0(a[step-1])+fmaj(a[step-1],b[step-1],c[step-1])+summ1(e[step-1])+fif(e[step-1],f[step-1],g[step-1])+h[step-1]+k[step]+w1[step];
        b[step] = a[step-1];
        c[step] = b[step-1];
        d[step] = c[step-1];
        e[step] = d[step-1]+summ1(e[step-1])+fif(e[step-1],f[step-1],g[step-1])+h[step-1]+k[step]+w1[step];
        f[step] = e[step-1];
        g[step] = f[step-1];
        h[step] = g[step-1];
    }
}

void run(){
    string tm1 ,tm2;
    tm1.resize(64);
    tm2.resize(64);
    for(int i=0;i<16;i++)
    {
                
        tm1[4*i] = (w1[i] >> 24) & 0xFF;
        tm1[4*i+1] = (w1[i] >> 16) & 0xFF;
        tm1[4*i+2] = (w1[i] >> 8) & 0xFF;
        tm1[4*i+3] = w1[i] & 0xFF;
        tm2[4*i] = (w2[i] >> 24) & 0xFF;
        tm2[4*i+1] = (w2[i] >> 16) & 0xFF;
        tm2[4*i+2] = (w2[i] >> 8) & 0xFF;
        tm2[4*i+3] = w2[i] & 0xFF;
    }
    /*string hw1 = "";
    string hw2 = "";
    //for(int i=0;i<16;i++)
    //    cout<<w1[i]<<" ";
    //cout<<endl;
    //for(int i=0;i<16;i++)
    //    cout<<w2[i]<<" ";
    //cout<<endl;
    UInt32 x= 1<<7|1<<3;
    //cout<<string_to_hex(x)<<endl;
    for(int i=0;i<16;i++){
        stringstream ss ;
        ss << hex << w1[i];
        string tmp = "";
        int cnt = 8-ss.str().size();
        while(cnt--)
            tmp+="0";
        tmp+=ss.str();
        hw1+=tmp;
        //hw1 += " ("+tmp+")"+ss.str();

    }
    for(int i=0;i<16;i++){
        stringstream ss ;
        ss << hex << w2[i];
        int cnt = 8-ss.str().size();
        string tmp = "";
        while(cnt--)
            tmp+="0";
        tmp+=ss.str();
        hw2+=tmp;
        //hw2 += " ("+tmp+")"+ss.str();
    }
    // hw1 = "657adf6306c066d790f0b70995a3e1d1c3017f24fad6c2bfdff436856abff0dae6cfc63fde8fb4c1c20ca05bf74815ccc2e789d9208e7105cc08b6cf70171840";
    // hw2 = "657adf6306c066d790f0b70995a3e1d1c3017f24fad6c2bfdff436856abff0dae6cfc63fde8fb4c1c20ca05cf74815cbc2e7e9d91f8ed106cc08b6cf70171840";
    cout<<hw1.length()<<endl<<hw2.length()<<endl;
    cout<<"hex values "<<endl;
    cout<<hw1<<endl<<hw2<<endl;
    string tm1,tm2;
    tm1.resize(64);
    tm2.resize(64);
    //cout<<m1.size()<<endl;
    //cout<<hd('0')<<endl<<hd('a')<<endl;
    for(int i=0;i<64;i++)
    {
      tm1[i] = hd(hw1[2*i])*16+hd(hw1[2*i+1]);
      
      tm2[i] = hd(hw2[2*i])*16+hd(hw2[2*i+1]);
      
      //cout<<hd(m1[2*i])<<" "<<hd(m1[2*i+1])<<endl;
    }
    //cout<<tm1<<endl;
    //cout<<tm2<<endl;*/
    std::cout<<SHA256_digest(tm1).toHex()<<"\n";
    std::cout<<SHA256_digest(tm2).toHex()<<"\n";
    assert(SHA256_digest(tm1).toHex()==
    SHA256_digest(tm2).toHex());
    
    
}

UInt32 calcPhi(int i)
{
    return summ0(a[i])+fmaj(a[i],b[i],c[i])+summ1(e[i])+fif(e[i],f[i],g[i])+h[i]+k[i+1];
}
UInt32 calC(int i){
    return e[i+5]-summ1(e[i+4])-fif(e[i+4],e[i+3],e[i+2])-2*a[i+1]-k[i+5]+summ0(a[i]);
}

vector<UInt32> guess(UInt32 D)
{
    vector<UInt32> l ;
    for(UInt32 g=0;g<(1<<16);g++)
    {
        UInt32 X = D+g,Y=(g>>3)^(g>>7),b_25_18;
        b_25_18 = (X^Y)&(0xff);
        for(UInt32 c0 = 0;c0<2;c0++)
        {
            X = (D>>19)+(b_25_18>>1)+c0;
            Y = (g>>5)^(b_25_18>>4);
            UInt32 b_29_26 = (X^Y)&0xf;
            for(UInt32 c1 = 0;c1<2;c1++)
            {
                X = (D>>23)+(b_25_18>>5)+c1;
                Y = (g>>9)^(b_29_26);
                UInt32 b_31_30 = (X^Y)&0x3;
                for(UInt32 c2 = 0;c2<2;c2++)
                {
                    X = (D>>8)+(g>>8)+c2;
                    Y = (g>>11)^(b_29_26);
                    UInt32 b_17_15 = (X^Y)&0x7;
                    UInt32 WG;
                    WG = g+b_17_15*(1<<15)+b_25_18*(1<<18)+b_29_26*(1<<26)+b_31_30*(1<<30);
                    if((sigma0(WG)-WG)==D)
                        l.push_back(WG);
                }
            }
        }
    }
    return l;
}

UInt32 ww1(int i)
{
    return sigma1(w1[i-2])+w1[i-7]+sigma0(w1[i-15])+w1[i-16];
}
UInt32 ww2(int i)
{
    return sigma1(w2[i-2])+w2[i-7]+sigma0(w2[i-15])+w2[i-16];
}

int main(){
    ofstream mf;
    mf.open("out2.txt");
    UInt32 delta[16];

    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
    

    /* setting a4-a12 and e8-e16*/
    
    {
        a[8] = valpha;
        a[9] = valpha;
        a[10] = -1;
        a[11] = vbeta;
        a[12] = vbeta;
        e[8] = vgamma;
        e[9] = vgamma+1;
        e[10] = -1;
        e[11] = vmu;
        e[12] = vlembda;
        e[13] = vlembda-1;
        e[14] = -1;
        e[15] = -1;
        e[16] = -2;
        w1[16] = e[16]-summ1(e[15])-fif(e[15],e[14],e[13])-a[12]-e[12]-k[16];
        w1[14] = e[14] - summ1(e[13]) - fif(e[13],e[12],e[11]) - a[10] - e[10] - k[14];
        w1[15] = e[15] - summ1(e[14])-fif(e[14],e[13],e[12])-a[11]-e[11]-k[15];
        int i = 7;
        for(int i=7;i>=4;i--)
        {
            a[i] = e[i+4]-a[i+4]+summ0(a[i+3])+fmaj(a[i+3],a[i+2],a[i+1]);
        }
    }
    UInt32 st = 0;
    bool gs = false;
    while(st<(400000)&&!gs)
    {
        cout<<st<<endl;
        st += 1;
        w1[0] = randomWord();
        a[2] = randomWord();
        a[3] = randomWord();
        hashEvaluation(0);
        UInt32 phi0,phi1,phi2;
        phi0 = calcPhi(0);
        e[7] = a[7] + a[3] -summ0(a[6]) - fmaj(a[6],a[5],a[4]);
        e[6] = a[6] + a[2] - summ0(a[5]) - fmaj(a[5],a[4],a[3]);
        UInt32 c4 = calC(4),D = w1[16]-(sigma1(w1[14])+c4+fmaj(a[4],a[3],a[2])-phi0+w1[0]);
        vector<UInt32> vgw1 = guess(D);
        for(UInt32 gw1 : vgw1)
        {
            w1[1] = gw1 ;
            hashEvaluation(1);
            phi1 = calcPhi(1);
            w1[2] = W_to_set_register_A(2,a[2]);
            hashEvaluation(2);
            phi2 = calcPhi(2);
            w1[3] = W_to_set_register_A(3,a[3]);
            UInt32 c5 = calC(5);
            w1[17] = sigma1(w1[15])+c5-w1[2]+fmaj(a[5],a[4],a[3])-phi1+sigma0(w1[2])+w1[1];
            w1[18] = sigma1(w1[16])+calC(6)-w1[3]+fmaj(a[6],a[5],a[4])-phi2+sigma0(w1[3])+w1[2];
            if((sigma1(w1[17]+1)-sigma1(w1[17])+del1)==0&&(sigma1(w1[18]-1)-sigma1(w1[18])+del2)==0)
            {
                cout<<"got the solution"<<endl;
                gs = true;
                break;
            }
        } 
    }
    if(gs)
    {
        hashEvaluation(3);
        w1[4] = W_to_set_register_A(4,a[4]);
        hashEvaluation(4);
        w1[5] = W_to_set_register_A(5,a[5]);
        hashEvaluation(5);
        w1[6] = W_to_set_register_A(6,a[6]);
        hashEvaluation(6);
        w1[7] = W_to_set_register_A(7,a[7]);
        hashEvaluation(7);
        w1[8] = W_to_set_register_A(8,a[8]);
        hashEvaluation(8);
        w1[9] = W_to_set_register_A(9,a[9]);
        hashEvaluation(9);
        w1[10] = W_to_set_register_A(10,a[10]);
        hashEvaluation(10);
        w1[11] = W_to_set_register_A(11,a[11]);
        hashEvaluation(11);
        w1[12] = W_to_set_register_A(12,a[12]);
        hashEvaluation(12);
        w1[13] = W_to_set_register_E(13,e[13]);
        hashEvaluation(13);
        for(int i=0;i<10;i++)
            delta[i] = 0;
        
        delta[10] = 1;
        delta[11] = -1;
        delta[12] = del1;
        delta[13] = del2;
        delta[14] = 0;
        delta[15] = 0;
        for(int i=0;i<=15;i++)
            w2[i] = w1[i] + delta[i];
        for(int i=16;i<=23;i++)
            w2[i] = ww2(i);
        for(int i=19;i<=23;i++)
            w1[i] = ww1(i);
        
        for(int i=0;i<=23;i++){
            mf<<"del"<<i<<" "<<w2[i]-w1[i]<<" "<<w2[i]<<" "<<w1[i]<<endl;
            cout<<"del"<<i<<" "<<w2[i]-w1[i]<<" "<<w2[i]<<" "<<w1[i]<<endl;
        }
            
        
        mf.close();
        run();
        cout<<"Success !!"<<endl;
    }
    
    
}
