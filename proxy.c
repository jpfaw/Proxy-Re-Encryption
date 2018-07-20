// gcc -o proxy proxy.c -ltepla -lssl -lgmp -lcrypto -std=c99

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <sys/time.h>
#include <tepla/ec.h>

#define DEBUG 0 // 0: false 1: true
#define MESSAGE_SIZE 1024
#define CODE_SIZE MESSAGE_SIZE/sizeof(int)

void print_red_color(const char *text);
void print_green_color(const char *text);
void create_mpz_t_random(mpz_t op, const mpz_t n);
unsigned long convert_hex_string_into_long_type(const char *x);
void convert_long_type_into_hex_string(char *result, const unsigned long x);

int main(void) {
/* --- セットアップ --- */
    int i;
//    char msg[MESSAGE_SIZE]="Hello World!";
    char msg[MESSAGE_SIZE]="abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
    int msg_len = strlen(msg);
    int roop_num = msg_len/sizeof(long) + 1;

/* --- 暗号化 --- */
    /* --- ペアリングを生成 --- */
    EC_PAIRING p;
    pairing_init(p, "ECBN254a");
    
    /* --- 上限値の設定 --- */
    mpz_t limit;
    mpz_init(limit);
    mpz_set(limit, *curve_get_order(p->g1));
    print_green_color("limit = "); gmp_printf ("%Zd\n", limit);
    
    /* --- 楕円曲線 E 上の点 P の生成 --- */
    EC_POINT P;
    point_init(P, p->g1);
    point_random(P);
    print_green_color("P =  "); point_print(P);
    
    /* --- 楕円曲線 E 上の点 Q の生成 --- */
    EC_POINT Q;
    point_init(Q, p->g2);
    point_random(Q);
    print_green_color("Q =  "); point_print(Q);
    
    /* --- aとrを生成 --- */
    mpz_t a, r;
    mpz_init(a);
    mpz_init(r);
    create_mpz_t_random(a, limit);
    create_mpz_t_random(r, limit);

    /* -- g = e(P, Q)^r を生成 --- */
    Element g;
    element_init(g, p->g3);
    pairing_map(g, P, Q, p);
    element_pow(g, g, r);       // r乗する
    print_green_color("g =  "); element_print(g);
    
    /* --- 平文をlong型にした後、16進数表記のchar型に変換 --- */
    //init
    unsigned long enc_msg[CODE_SIZE];
    memset(enc_msg,0,sizeof(enc_msg));
    //encode(msg)
    memcpy(enc_msg,msg,msg_len);
    if(DEBUG) for(i=0;i<roop_num;i++) printf("enc_msg[%d]:%ld\n",i,enc_msg[i]);
    /* --- 16進数表記のchar型平文をElement型に変換 --- */
    Element element_msg[roop_num/12+1];
    char element_assign_str[1000] = "";
    int element_msg_index_counter = 0;
    for(i=0;i<roop_num;i++) {
        char tmp2[100];
        convert_long_type_into_hex_string(tmp2, enc_msg[i]);
        strcat(element_assign_str, tmp2);
        if(i != 0 && i%11==0) {
            element_init(element_msg[element_msg_index_counter], p->g3);
            element_set_str(element_msg[element_msg_index_counter++], element_assign_str);
        } else {
            strcat(element_assign_str, " ");
        }
    }
    if(i%11!=0){ // 残りカスの処理
        for(i = 12-i%11;i>0;i--) {
            strcat(element_assign_str, "0");
            if(i!=1) strcat(element_assign_str, " ");
        }
        if(DEBUG) printf("element_assign_str: %s\n", element_assign_str);
        element_init(element_msg[element_msg_index_counter], p->g3);
        element_set_str(element_msg[element_msg_index_counter++], element_assign_str);
    }
    if(DEBUG) for(i=0;i<element_msg_index_counter;i++){
        printf("element_msg[%d]: ",i);
        element_print(element_msg[i]);
    }
    
    /* --- 文字列と鍵を掛け算 --- */
    Element element_msg_key_calc_result[element_msg_index_counter];
    for(i=0;i<element_msg_index_counter;i++) {
        element_init(element_msg_key_calc_result[i], p->g3);
        element_mul(element_msg_key_calc_result[i], element_msg[i], g);
    }
    if(DEBUG) for(i=0;i<element_msg_index_counter;i++){
        printf("element_msg_key_calc_result[%d]: ",i);
        element_print(element_msg_key_calc_result[i]);
    }

    /* --- r(aQ) を計算 --- */
    EC_POINT raQ;
    point_init(raQ, p->g2);
    point_mul(raQ, a, Q);
    point_mul(raQ, r, raQ);
    print_green_color("raQ = "); point_print(raQ);

/* --- 再暗号化 --- */
    /* --- bを生成 --- */
    mpz_t b;
    mpz_init(b);
    create_mpz_t_random(b, limit);

    /* --- 1/aを計算 --- */
    mpz_t a_one;
    mpz_init(a_one);
    mpz_invert(a_one, a, limit);

    /* --- (1/a)bP を計算(再暗号化鍵) --- */
    EC_POINT reEncKey;
    point_init(reEncKey, p->g1);
    point_mul(reEncKey, b, P);
    point_mul(reEncKey, a_one, reEncKey);
    print_green_color("reEncKey = "); point_print(reEncKey);

    /* --- g^(rb)を計算 --- */
    Element grb;
    element_init(grb, p->g3);
    pairing_map(grb, reEncKey, raQ, p);
    print_green_color("grb =  "); element_print(grb);

/* --- 復号 --- */
    /* --- 1/bを計算 --- */
    mpz_t b_one;
    mpz_init(b_one);
    mpz_invert(b_one, b, limit);

    /* --- (g^(rb))^(1/b) = g^r --- */
    Element g3;
    element_init(g3, p->g3);
    element_pow(g3, grb, b_one);
    print_green_color("g3 =  "); element_print(g3);
    if(element_cmp(g, g3) == 0) print_green_color("g3CHECK: OK\n");
    else{print_green_color("g3CHECK: "); print_red_color("NG\n");};
    
    Element g3_inv;
    element_init(g3_inv, p->g3);
    element_inv(g3_inv, g3);
    
    /* --- 文字列と鍵を割り算((m*g^r)*(1/g^r) --- */
    Element element_crypto_g3_calc_result[element_msg_index_counter];
    for(i=0;i<element_msg_index_counter;i++) {
        element_init(element_crypto_g3_calc_result[i], p->g3);
        element_mul(element_crypto_g3_calc_result[i], element_msg_key_calc_result[i], g3_inv);
    }
    if(DEBUG) for(i=0;i<element_msg_index_counter;i++){
        printf("element_crypto_g3_calc_result[%d]: ",i);
        element_print(element_crypto_g3_calc_result[i]);
    }
    
    /* --- 計算結果をchar型に変換 --- */
    unsigned long dec_msg_long[CODE_SIZE];
    long dec_msg_long_counter = 0;
    for(i=0;i<element_msg_index_counter;i++){
        int element_crypto_g3_calc_result_size = element_get_str_length(element_crypto_g3_calc_result[i]);
        char *element_crypto_g3_calc_result_str;
        if((element_crypto_g3_calc_result_str = (char *)malloc(element_crypto_g3_calc_result_size+1)) == NULL) {
            printf("メモリが確保できませんでした。\n");
            return 0;
        }
        element_get_str(element_crypto_g3_calc_result_str, element_crypto_g3_calc_result[i]);
        /* --- elementから変換したcharをスペースで分割してlong型に変換 --- */
        char dec_msg_char[12][128];
        char *ptr;
        ptr = strtok(element_crypto_g3_calc_result_str, " ");
        strcpy(dec_msg_char[0], ptr); i=1;
        while(ptr != NULL) {
            ptr = strtok(NULL, " ");
            if(ptr != NULL) strcpy(dec_msg_char[i], ptr);
            i++;
        }
        for(i=0;i<12;i++) if(strcmp(dec_msg_char[i], "0")!=0)
            dec_msg_long[dec_msg_long_counter++] = convert_hex_string_into_long_type(dec_msg_char[i]);
        free(element_crypto_g3_calc_result_str);
    }
    if(DEBUG) for(i=0;i<dec_msg_long_counter;i++) printf("dec_msg_long[%d]: %ld\n",i,dec_msg_long[i]);

    /* --- decode --- */
    char msg_decode[CODE_SIZE];
    memset(msg_decode,0,sizeof(msg_decode));
    memcpy(msg_decode,dec_msg_long,strlen(msg));
    print_green_color("message = "); printf("%s\n", msg_decode);

/* --- 領域の解放 --- */
    mpz_clears(limit, a, r, a_one, b, b_one, NULL);
    point_clear(P);
    point_clear(Q);
    point_clear(raQ);
    point_clear(reEncKey);
    element_clear(g);
    element_clear(grb);
    element_clear(g3);
    element_clear(g3_inv);
    for(i=0;i<element_msg_index_counter;i++) element_clear(element_msg[i]);
    for(i=0;i<element_msg_index_counter;i++) element_clear(element_msg_key_calc_result[i]);
    for(i=0;i<element_msg_index_counter;i++) element_clear(element_crypto_g3_calc_result[i]);
    pairing_clear(p);

    print_green_color("--- 正常終了 ---\n");
}


/* -----------------------------------------------
 * mpz_tでランダムな値を生成する関数
 * $0 生成した値を入れる変数
 * $1 上限値
 * 参考サイト https://sehermitage.web.fc2.com/etc/gmp_src.html
 -----------------------------------------------*/
void create_mpz_t_random(mpz_t op, const mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    
    struct timeval tv, tv2;
    gettimeofday(&tv2, NULL);
    
    do {
        gettimeofday(&tv, NULL);
    } while (tv.tv_usec == tv2.tv_usec);
    
    gmp_randseed_ui(state, tv.tv_usec);
    mpz_urandomm(op, state, n);
    
    gmp_randclear(state);
}

/* -----------------------------------------------
 * 文字列を緑色で出力する関数
 * $0 出力したい文字列
 -----------------------------------------------*/
void print_green_color(const char *text) {
    printf("\x1b[32m%s\x1b[39m", text);
}

/* -----------------------------------------------
 * 文字列を赤色で出力する関数
 * $0 出力したい文字列
 -----------------------------------------------*/
void print_red_color(const char *text) {
    printf("\x1b[31m%s\x1b[39m", text);
}

/* -----------------------------------------------
 * 符号なしlong型整数を16進数表記のchar型文字列に変換する関数
 * $0 変換結果を入れるchar型配列のアドレス
 * $1 変換したい符号なしlong型整数
 -----------------------------------------------*/
void convert_long_type_into_hex_string(char *result, const unsigned long x){
    unsigned long original = x;
    *result = '\0';
    do{
        char tmp;
        sprintf(&tmp, "%X", original%16);
        strcat(result, &tmp);
    }while((original /= 16) != 0);
    char t, *p, *q;
    for (p = result, q = &(result[strlen(result)-1]); p < q; p++, q--) t = *p, *p = *q, *q = t;
}

/* -----------------------------------------------
 * 16進数表記のchar型文字列を符号なしlong型整数に変換する関数
 * $0 変換したいchar型配列のアドレス
 * @return 変換結果の符号なしlong型整数
 -----------------------------------------------*/
unsigned long convert_hex_string_into_long_type(const char *x){
    unsigned long result=0, exp=1;
    int length = strlen(x)-1, i;
    for(i=length; i>=0; i--){
        char tmp_char = *(x+i);
        unsigned long tmp_long;
        sscanf(&tmp_char, "%X", &tmp_long);
        result += tmp_long*exp;
        exp *= 16;
    }
    return result;
}
