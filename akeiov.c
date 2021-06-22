//2020-10-03
//compile: gcc akeiov.c -lmiracl -o akeiov

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

void hash(unsigned char* str, int len, unsigned char* result);
void h1(big id, epoint* Xi, epoint* Pi, unsigned char* result);
void h2(big ida, big idb, epoint* Xa, epoint* Xb, epoint* Ra, epoint* Rb, epoint* Ta1, epoint* Ta2, epoint* Tb1, epoint* Tb2,  epoint* K1, epoint* K2, unsigned char* result);
int get_biglen(big b);
int get_pointlen(epoint* e);
void print_point(epoint* e);
void bigmod(big* b, big* modular);
void hashbytes_to_big(int len, unsigned char* hashbytes, big* result);

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
    struct timeval start, end, start1, end1, start2, end2;
    int sumlen;
    epoint* P, *Ppub, *Ptemp1, *Ptemp2, *Ptemp3, *Xa, *Xb, *Ra, *Rb, *Na, *Nb, *Ta1, *Ta2, *Tb1, *Tb2, *Kab1, *Kba1, *Kab2, *Kba2;
    big IDa, IDb, xa, xb, s, ra, rb, ha, hb, hab, hba, pa, pb, na, nb, big_kab1, big_kba1, big_kab2, big_kba2, temp1, temp2, SKab, SKba;
    big eparam_a, eparam_b, eparam_p, eparam_x, eparam_y, eparam_q;
    miracl *mip;

    unsigned char hash_result[HASH_LEN];
    
#ifndef MR_NOFULLWIDTH   
    mip=mirsys(20,0);
#else
    mip=mirsys(20,MAXBASE);
#endif
    xa = mirvar(0);
    xb = mirvar(0);
    s = mirvar(0);
    ra = mirvar(0);
    rb = mirvar(0);
    ha = mirvar(0);
    hb = mirvar(0);
    hab = mirvar(0);
    hba = mirvar(0);
    pa = mirvar(0);
    pb = mirvar(0);
    na = mirvar(0);
    nb = mirvar(0);

    big_kab1 = mirvar(0);
    big_kba1 = mirvar(0);
    big_kab2 = mirvar(0);
    big_kba2 = mirvar(0);

    temp1 = mirvar(0);
    temp2 = mirvar(0);

    IDa = mirvar(0);
    IDb = mirvar(0);
    SKab = mirvar(0);
    SKba = mirvar(0);

    eparam_a = mirvar(0);
    eparam_b = mirvar(0);
    eparam_p = mirvar(0);
    eparam_q = mirvar(0);
    eparam_x = mirvar(0);
    eparam_y = mirvar(0);

    time(&seed);
    irand((unsigned long)seed);

    printf("PKG Init Phase......\n");
    gettimeofday(&start, NULL);  
    
    //convert(-3, eparam_a);
    mip->IOBASE=16;
    cinstr(eparam_a, eca);
    cinstr(eparam_b, ecb);
    cinstr(eparam_p, ecp);
    cinstr(eparam_q, ecq);      
    ecurve_init(eparam_a, eparam_b, eparam_p, MR_BEST);  /* Use PROJECTIVE if possible, else AFFINE coordinates */

    P = epoint_init();
    cinstr(eparam_x, ecx);
    cinstr(eparam_y, ecy);
    //mip->IOBASE=10;
    epoint_set(eparam_x, eparam_y, 0, P);

    bigbits(BIGLENG, s);
    Ppub = epoint_init();
    ecurve_mult(s, P, Ppub);

    gettimeofday(&end, NULL);
    printf("PKG init time: %lfms\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);
    fprintf(stderr, "%0.2lf, ", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);

    printf("Private Key Extraction Phase......\n");
    gettimeofday(&start, NULL);
    //printf("Alice Produces Partial Private Key......\n");

    // int i;
    // for (i = 0; i < 100; i++)
    // {
        bigbits(BIGLENG, xa);
        bigbits(IDLEN, IDa);
        Xa = epoint_init();
        ecurve_mult(xa, P, Xa);
    
        //printf("Bob Produces Partial Private Key......\n");

        bigbits(BIGLENG, xb);
        bigbits(IDLEN, IDb);
        Xb = epoint_init();
        ecurve_mult(xb, P, Xb);

        //printf("PKG Produces Partial Private Key......\n");

        bigbits(BIGLENG, ra);
        bigbits(BIGLENG, rb);
        Ra = epoint_init();
        Rb = epoint_init();

        ecurve_mult(ra, P, Ra);
        ecurve_mult(rb, P, Rb);

        h1(IDa, Xa, Ra, hash_result);
        hashbytes_to_big(HASH_LEN, hash_result, &ha);
        h1(IDb, Xb, Rb, hash_result);
        hashbytes_to_big(HASH_LEN, hash_result, &hb);

        multiply(ha, s, ha);
        add(ra, ha, pa);
        bigmod(&pa, &eparam_q);

        multiply(hb, s, hb);
        add(rb, hb, pb);
        bigmod(&pb, &eparam_q);

    //}
   

    gettimeofday(&end, NULL);
    printf("private key extraction time: %lfms\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);
    fprintf(stderr, "%0.2lf, ", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);

    printf("Key Agreement Phase......\n");
    gettimeofday(&start, NULL);
    //printf("Alice Computes Ephemeral Key......\n");

    bigbits(BIGLENG, na);
    Na = epoint_init();
    Ta1 = epoint_init();
    Ta2 = epoint_init();

    ecurve_mult(na, P, Na);
    ecurve_mult(pa, Na, Ta1);
    ecurve_mult(xa, Na, Ta2);
   

    //printf("Bob Computes Ephemeral Key......\n");
    bigbits(BIGLENG, nb);
    Nb = epoint_init();
    Tb1 = epoint_init();
    Tb2 = epoint_init();
 
    ecurve_mult(nb, P, Nb);
    ecurve_mult(pb, Nb, Tb1);
    ecurve_mult(xb, Nb, Tb2);
    
    
    //printf("Alice Computes Secret Message......\n");
    h1(IDb, Xb, Rb, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &hab);
    Ptemp1 = epoint_init();
    Ptemp2 = epoint_init();

    ecurve_mult(hab, Ppub, Ptemp1);
    ecurve_add(Rb, Ptemp1);
    multiply(na, pa, temp1);
    bigmod(&temp1, &eparam_q);

  
    Kab1 = epoint_init();
    ecurve_mult(temp1, Ptemp1, Kab1);
    ecurve_mult(pa, Tb1, Ptemp2);
    ecurve_add(Ptemp2, Kab1);

    Kab2 = epoint_init();
    multiply(xa, na, temp1);
    bigmod(&temp1, &eparam_q);
    ecurve_mult(temp1, Tb2, Kab2);
    

    //printf("Bob Computes Secret Message......\n");
    h1(IDa, Xa, Ra, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &hba);
    Ptemp1 = epoint_init();
    Ptemp2 = epoint_init();
    
    ecurve_mult(hba, Ppub, Ptemp1);
    ecurve_add(Ra, Ptemp1);
    multiply(nb, pb, temp1);
    bigmod(&temp1, &eparam_q);
    Kba1 = epoint_init();
    ecurve_mult(temp1, Ptemp1, Kba1);
    
    ecurve_mult(pb, Ta1, Ptemp2);
    ecurve_add(Ptemp2, Kba1);

    Kba2 = epoint_init();
    multiply(xb, nb, temp1);
    bigmod(&temp1, &eparam_q);
    ecurve_mult(temp1, Ta2, Kba2);


    h2(IDa, IDb, Xa, Xb, Ra, Rb, Ta1, Ta2, Tb1, Tb2, Kab1, Kab2, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &SKab);
    h2(IDa, IDb, Xa, Xb, Ra, Rb, Ta1, Ta2, Tb1, Tb2, Kba1, Kba2, hash_result);
    hashbytes_to_big(HASH_LEN, hash_result, &SKba);

    gettimeofday(&end, NULL);
    printf("Key agreement time: %lfms\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);
    fprintf(stderr, "%0.2lf\n", (1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec)/1000.0);

    printf("SKab: ");
    cotnum(SKab, stdout);
    printf("SKba: ");
    cotnum(SKba, stdout);

    printf("Communication traffic: %d\n", 2 * (get_biglen(IDa) + get_pointlen(Xa) + get_pointlen(Ra) + get_pointlen(Ta1) + get_pointlen(Ta2)));
    printf("Key memeory cost: %d\n", 2 * (get_biglen(xa) + get_biglen(pa) + get_pointlen(Xa) + get_pointlen(Ra)));
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

void h1(big id, epoint* Xi, epoint* Pi, unsigned char* result)
{
    unsigned char ustr[4 * MAXLEN];
    big big_Pi, big_Xi;

    big_Pi = mirvar(0);
    big_Xi = mirvar(0);

    cotstr(id, ustr);
    
    epoint_get(Xi, big_Xi, big_Xi);
    cotstr(big_Xi, ustr + strlen(ustr));

    epoint_get(Pi, big_Pi, big_Pi);
    cotstr(big_Pi, ustr + strlen(ustr));

    hash(ustr, strlen(ustr), result);
}

void h2(big ida, big idb, epoint* Xa, epoint* Xb, epoint* Ra, epoint* Rb, epoint* Ta1, epoint* Ta2, epoint* Tb1, epoint* Tb2,  epoint* K1, epoint* K2, unsigned char* result)
{
    unsigned char ustr[4 * MAXLEN];
    big x, y;

    x = mirvar(0);
    y = mirvar(0);

    cotstr(ida, ustr);
    cotstr(idb, ustr + strlen(ustr));

    epoint_get(Xa, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(Xb, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(Ra, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(Rb, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(Ta1, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(Ta2, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(Tb1, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(Tb2, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(K1, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));

    epoint_get(K2, x, y);
    cotstr(x, ustr + strlen(ustr));
    cotstr(y, ustr + strlen(ustr));
    
    hash(ustr, strlen(ustr), result);
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