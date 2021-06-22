//2020 11-24
//compile: gcc li.c -lmiracl -o li
//A Provably Secure and Lightweight Identity-Based Two-Party Authenticated Key Agreement Protocol for Vehicular Ad Hoc Networks

# include<stdio.h>
# include<stdlib.h>
# include<string.h>
# include<time.h>
# include<sys/time.h>
# include<miracl/miracl.h>

# define BIGLENG 160
# define IDLEN 160

# define HASH_LEN 20
# define MAXLEN 1024

void hash(unsigned char* ustr, int len, unsigned char* result);
void h2(epoint* e, unsigned char* result);
void h1(big b, epoint* e, unsigned char* result);
void h3(big ida, big idb, epoint* sk, epoint* apk, epoint* st, unsigned char* result);
int get_biglen(big b);
int get_pointlen(epoint* e);
void print_point(epoint* e);
void hashbytes_to_big(int len, unsigned char* hashbytes, big* result);
void bigmod(big* b, big* modular);

// Use elliptic curve of the form y^2=x^3+Ax+B
// parameter p, p is a prime
char *ecp="E95E4A5F737059DC60DFC7AD95B3D8139515620F";

// parameter A
char *eca ="340E7BE2A280EB74E2BE61BADA745D97E8F7C300";

// parameter B
char *ecb="1E589A8595423412134FAA2DBDEC95C8D8675E58";

// elliptic curve - point of prime order (x,y) 
char *ecx="BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3";
char *ecy="1667CB477A1A8EC338F94741669C976316DA6321";

// group oder q
char *ecq="E95E4A5F737059DC60DF5991D45029409E60FC09";

int main(int argc, char* argv[])
{
    time_t seed;
    struct timeval start, end;
    int sumlen;
    epoint* P, *Ppub, *saP, *sbP, *Ra, *Rb, *Ta, *Tb, *PKb, *PKa, *SKa, *SKb, *Ptemp1, *Ptemp2, *Ptemp3;
    big IDa, IDb, sa, sb, s, ra, rb, ha, hb, hak, hbk, a, b, hba, hab, temp1, temp2, SKab, SKba;
    big eparam_a, eparam_b, eparam_p, eparam_x, eparam_y, eparam_q;
    miracl *mip;

    unsigned char hash_result[HASH_LEN];
    
#ifndef MR_NOFULLWIDTH   
    mip=mirsys(36,0);
#else
    mip=mirsys(36,MAXBASE);
#endif
    sa = mirvar(0);
    sb = mirvar(0);
    s = mirvar(0);
    ra = mirvar(0);
    rb = mirvar(0);
    ha = mirvar(0);
    hb = mirvar(0);
    hak = mirvar(0);
    hbk = mirvar(0);
    a = mirvar(0);
    b = mirvar(0);
    hab = mirvar(0);
    hba = mirvar(0);

    temp1 = mirvar(0);
    temp2 = mirvar(0);

    IDa = mirvar(0);
    IDb = mirvar(0);
    SKab = mirvar(0);
    SKba = mirvar(0);

    eparam_a = mirvar(0);
    eparam_b = mirvar(0);
    eparam_p = mirvar(0);
    eparam_x = mirvar(0);
    eparam_y = mirvar(0);
    eparam_q = mirvar(0);

    time(&seed);
    irand((unsigned long)seed);

    printf("PKG Init Phase......\n");
    gettimeofday(&start, NULL);

    //convert(-3, eparam_a);
    mip->IOBASE=16;
    cinstr(eparam_b, ecb);
    cinstr(eparam_p, ecp);
    cinstr(eparam_a, eca);      
    ecurve_init(eparam_a, eparam_b, eparam_p, MR_BEST);  /* Use PROJECTIVE if possible, else AFFINE coordinates */

    P = epoint_init();
    cinstr(eparam_x, ecx);
    cinstr(eparam_y, ecy);
    cinstr(eparam_q, ecq);
    //mip->IOBASE=10;
    epoint_set(eparam_x, eparam_y, 0, P);

    bigbits(BIGLENG, s);
    Ppub = epoint_init();
    ecurve_mult(s, P, Ppub);

    gettimeofday(&end, NULL);
    printf("PKG init: %lfms\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);
    fprintf(stderr, "%0.2lf, ", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);

    
    printf("Private Key Extraction Phase......\n");
    gettimeofday(&start, NULL);

    int i;
    for (i = 0; i < 100; i++)
    {
        //vehicle A
        bigbits(BIGLENG, ra);
        bigbits(BIGLENG, IDa);
        Ra = epoint_init();
        ecurve_mult(ra, P, Ra);

        
        h1(IDa, Ra, hash_result);
        hashbytes_to_big(HASH_LEN, hash_result, &hak);

        multiply(hak, s, temp1);
        add(temp1, ra, sa);
        bigmod(&sa, &eparam_q);

        saP = epoint_init();
        Ptemp1 = epoint_init();
        ecurve_mult(sa, P, saP);
        h1(IDa, Ra, hash_result);
        hashbytes_to_big(HASH_LEN, hash_result, &ha);
        ecurve_mult(ha, Ppub, Ptemp1);
        ecurve_add(Ra, Ptemp1);

        // if (epoint_comp(saP, Ptemp1) == 1)
        //     printf("Correct!\n");
        // else 
        //     printf("Incorrect!\n");

        //vehicle B
        bigbits(BIGLENG, rb);
        bigbits(BIGLENG, IDb);
        Rb = epoint_init();
        ecurve_mult(rb, P, Rb);
        h1(IDb, Rb, hash_result);
        hashbytes_to_big(HASH_LEN, hash_result, &hbk);

        multiply(hbk, s, temp1);
        add(temp1, rb, sb);
        bigmod(&sb, &eparam_q);

        sbP = epoint_init();
        Ptemp1 = epoint_init();
        ecurve_mult(sb, P, sbP);
        h1(IDb, Rb, hash_result);
        hashbytes_to_big(HASH_LEN, hash_result, &hb);
        ecurve_mult(hb, Ppub, Ptemp1);
        ecurve_add(Rb, Ptemp1);

        // if (epoint_comp(sbP, Ptemp1) == 1)
        //     printf("Correct!\n");
        // else 
        //     printf("Incorrect!\n");
        epoint_free(Ptemp1);
    }
    
    
    gettimeofday(&end, NULL);
    printf("private key extraction time: %lfms\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);
    fprintf(stderr, "%0.2lf, ", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0 + 0.36);

    printf("Key Agreement Phase......\n");
    gettimeofday(&start, NULL);

    bigbits(BIGLENG, a);
    Ta = epoint_init();
    ecurve_mult(a, P, Ta);

    bigbits(BIGLENG, b);
    Tb = epoint_init();
    ecurve_mult(b, P, Tb);

    PKb = epoint_init();
    h1(IDb, Rb, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &hab);
    ecurve_mult(hab, Ppub, PKb);
    ecurve_add(Rb, PKb);

    //print_point(PKb);
    //print_point(sbP);

    Ptemp1 = epoint_init();
    SKa = epoint_init();
    ecurve_mult(sa, PKb, Ptemp1);
    h2(Ptemp1, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &temp1);
    multiply(temp1, a, temp2);
    bigmod(&temp2, &eparam_q);
    ecurve_mult(temp2, Tb, SKa);
    epoint_free(Ptemp1);

    PKa = epoint_init();
    h1(IDa, Ra, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &hba);
    ecurve_mult(hba, Ppub, PKa);
    ecurve_add(Ra, PKa);

    //print_point(PKa);
    //print_point(saP);

    Ptemp1 = epoint_init();
    SKb = epoint_init();
    ecurve_mult(sb, PKa, Ptemp1);
    h2(Ptemp1, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &temp1);
    multiply(temp1, b, temp2);
    bigmod(&temp2, &eparam_q);
    ecurve_mult(temp2, Ta, SKb);
    epoint_free(Ptemp1);

    Ptemp1 = epoint_init();
    Ptemp2 = epoint_init();
    ecurve_mult(a, PKb, Ptemp1);
    ecurve_mult(sa, Tb, Ptemp2);
    h3(IDa, IDb, SKa, Ptemp1, Ptemp2, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &SKab);
    epoint_free(Ptemp2);
    epoint_free(Ptemp1);

    Ptemp1 = epoint_init();
    Ptemp2 = epoint_init();
    ecurve_mult(b, PKa, Ptemp1);
    ecurve_mult(sb, Ta, Ptemp2);
    h3(IDa, IDb, SKb, Ptemp2, Ptemp1, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &SKba);
    epoint_free(Ptemp2);
    epoint_free(Ptemp1);

    gettimeofday(&end, NULL);
    printf("Key agreement time: %lfms\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);
    fprintf(stderr, "%0.2lf\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);

    printf("skab: ");
    cotnum(SKab, stdout);
    printf("skba: ");
    cotnum(SKba, stdout);

    printf("Communication traffic: %d\n", 2 * (get_biglen(IDa) + get_pointlen(Ra) + get_pointlen(Ta)));
    printf("Key memeory cost: %d\n", 2 * (get_biglen(sa) + get_pointlen(Ra) + get_pointlen(PKa)));
    return 0;
}

void hash(unsigned char* ustr, int len, unsigned char* result)
{
    sha sh;
    int i;

    shs_init(&sh);
    for (i = 0; i < len; i++)
        shs_process(&sh, ustr[i]);
    shs_hash(&sh, result);
}

void h1(big b, epoint* e, unsigned char* result)
{
    epoint* be;
    
    be = epoint_init();
    ecurve_mult(b, e, be);
    h2(be, result);
}

void h2(epoint* e, unsigned char* result)
{
    big ex, ey;
    int lenx, leny;
    unsigned char ustr[MAXLEN];
    unsigned char* uptr;

    uptr = ustr;
    ex = mirvar(0);
    ey = mirvar(0);
    epoint_get(e, ex, ey);
    cotstr(ex, uptr);
    lenx = strlen(ustr);
    cotstr(ey, uptr + lenx);
    leny = strlen(ustr) - lenx;
    hash(ustr, lenx + leny, result);
}

void h3(big ida, big idb, epoint* sk, epoint* apk, epoint* st, unsigned char* result)
{
    big x, y;
    int len;
    unsigned char ustr[4 * MAXLEN];
    unsigned char* uptr;

    uptr = ustr;
    x = mirvar(0);
    y = mirvar(0);
    cotstr(ida, uptr);
    len = strlen(ustr);
    cotstr(idb, uptr + len);
    len = strlen(ustr);

    epoint_get(sk, x, y);
    cotstr(x, uptr + len);
    len = strlen(ustr);
    cotstr(y, uptr + len);
    len = strlen(ustr);

    epoint_get(apk, x, y);
    cotstr(x, uptr + len);
    len = strlen(ustr);
    cotstr(y, uptr + len);
    len = strlen(ustr);

    epoint_get(st, x, y);
    cotstr(x, uptr + len);
    len = strlen(ustr);
    cotstr(y, uptr + len);
    len = strlen(ustr);

    hash(ustr, len, result);
}

void print_point(epoint* e)
{
    big ex, ey;
    unsigned char buffer1[MAXLEN/2];
    unsigned char buffer2[MAXLEN/2];

    ex = mirvar(0);
    ey = mirvar(0);
    epoint_get(e, ex, ey);
    cotstr(ex, buffer1);
    cotstr(ey, buffer2);
    printf("[%s, %s]\n", buffer1, buffer2);
}

int get_biglen(big b)
{
    unsigned char ustrtemp[MAXLEN];
    // printf("%d ", big_to_bytes(MAXLEN, b, ustrtemp, 0));
    // printf("\n");
    return big_to_bytes(MAXLEN, b, ustrtemp, 0);
}


int get_pointlen(epoint* e)
{
    big big_ex, big_ey;

    big_ex = mirvar(0);
    big_ey = mirvar(0);
    epoint_get(e, big_ex, big_ey);
    return get_biglen(big_ex) + get_biglen(big_ey);
}

void hashbytes_to_big(int len, unsigned char* hashbytes, big* result)
{
    unsigned char* strbytes;
    int i;

    strbytes = (unsigned char*)malloc((len * 2 + 1)* sizeof(unsigned char));
    for(i = 0; i < len; i++)
        snprintf(strbytes + i * 2, (len -  i) * 2 + 1, "%02X", hashbytes[i]);
    cinstr(*result, strbytes);
}

void bigmod(big* b, big* modular)
{
    divide(*b, *modular, *modular);
}