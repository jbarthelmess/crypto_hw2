// TOY DES Cryptography and Network Security 1 HW1 Josh Barthelmess
//---------------------------------- PERMUTION FUNCTIONS -----------------------
/*
    Driving permute function
    block is the number to be permuted
    order is an array carrying the results scrambled bit order 
    result_len is the length of the resulting scrambled block
    
    order should hold the order as order[0] holds MOST significant bit and order[result_len-1] 
    holds LEAST significant bit
    
*/
#include<stdlib.h>
int permute(int block, int* order, int result_len) 
{
    int i = 0;
    int mask = 1;
    int perm = 0;
    int holder = 0;
    
    // using a bitmask to grab the bits as they are needed
    for(i = 0; i< result_len; i++)
    {
        perm = perm << 1; // make space for next bit
        mask = mask <<  (order[i]-1); //move mask in the correct place
        holder = mask & block; // get bit
        if(holder != 0) perm = perm +1; // if it was a one in that position, add it to perm
        mask = 1; // reset mask
    }
    return perm;
}

int plain_text_init_perm(int block)
{
    // permutation order is 7 5 8 4 1 3 6 2 (most to least sig bit)
    int order[8];
    order[0] = 7;
    order[1] = 5;
    order[2] = 8;
    order[3] = 4;
    order[4] = 1;
    order[5] = 3;
    order[6] = 6;
    order[7] = 2;
    
    return permute(block, order, 8);
}

int inverse_init_perm(int block)
{
    // permutation order is 6 8 2 7 5 3 1 4
    int order[8];
    order[0] = 6;
    order[1] = 8;
    order[2] = 2;
    order[3] = 7;
    order[4] = 5;
    order[5] = 3;
    order[6] = 1;
    order[7] = 4;
    
    return permute(block, order, 8);
}

int key_P10_perm(int key)
{
    //permutation order is 6 8 9 1 10 4 7 2 5 3
    int order[10];
    order[0] = 6;
    order[1] = 8;
    order[2] = 9;
    order[3] = 1;
    order[4] = 10;
    order[5] = 4;
    order[6] = 7;
    order[7] = 2;
    order[8] = 5;
    order[9] = 3;
    
    return permute(key, order, 10);
}

int key_P8_perm(int key) // This function ignores the two least significant bits
{
    // permutation order is 9 10 5 8 4 7 3 6
    int order[8];
    order[0] = 9;
    order[1] = 10;
    order[2] = 5;
    order[3] = 8;
    order[4] = 4;
    order[5] = 7;
    order[6] = 3;
    order[7] = 6;
    
    // permute should still work even tho result is smaller than block size
    return permute(key, order, 8);
}

int half_P4_perm(int half)
{
    //permutation order is 1 3 4 2
    int order[4];
    order[0] = 1;
    order[1] = 3;
    order[2] = 4;
    order[3] = 2;
    
    return permute(half, order, 4);
}

int key_shift(int key_half)
{
    // This function shifts key half bits one to the left
    // wrapping each bit back to the right as needed
    int up = 0;
    if(key_half >= 16)
        up = 1;
        
    key_half = key_half << 1;
    key_half += up;
    return key_half & 31; // removes the potential 1 in the sixth binary place 
}

void get_keys(int* k1, int* k2, int key)
{
    int key_perm = key_P10_perm(key);
    
    // splits 10 bit key into 5 bit halves
    int mask = 31; // 00011111
    int right = mask & key_perm; // right 5 bits
    mask = mask << 5;
    int left = mask & key_perm; // left 5 bits
    left = left >> 5;
    
    // first left shift for first derivative key
    left = key_shift(left);
    right = key_shift(right);
    left = left << 5;
    *k1 = key_P8_perm(left + right);
    
    left = left >> 5;
    
    // second left shift for second derivative key
    left = key_shift(left);
    right = key_shift(right);
    left = left << 5;
    *k2 = key_P8_perm(left+right);
}

//---------------------------- F BLOCK FUNCTIONS -------------------------------

int f_expand(int block)
{
    // right permutation order is 1 4 3 2
    int order[4];
    order[0] = 1;
    order[1] = 4;
    order[2] = 3;
    order[3] = 2;
    
    int right_half = permute(block, order, 4);
    
    // left permutation order is 3 2 1 4
    order[0] = 3;
    order[1] = 2;
    order[2] = 1;
    order[3] = 4;
    
    int left_half = permute(block, order, 4);
    left_half = left_half << 4; // shifting up to add right half
    
    return (left_half + right_half);
}

int bit_select(int** table, int half)
{
    int mask = 9; // bitwise AND selects outer two bits (1001) for row
    int row = mask & half;
    
    int up = 0; //need this to preserve smallest bit as it is shifted off when getting the number
    if(row %2 != 0) up = 1;
    row = row >> 2;
    row += up;
    
    mask = 6; // bitwise AND selects inner two bits (0110) for column
    int col = mask & half;
    col = col >> 1;
    
    return table[row][col]; 
    
}

int f(int half, int key)
{
    int** s_0;
    int** s_1;
    s_0 = malloc(sizeof(int)*4);
    s_1 = malloc(sizeof(int)*4);
    
    int i;
    for(i = 0; i< 4; i++)
    {
        s_0[i] = malloc(sizeof(int)*4);
        s_1[i] = malloc(sizeof(int)*4);
    }
    
    // initialize substitution boxes
    s_0[0][0] = 1;
    s_0[0][1] = 0;
    s_0[0][2] = 3;
    s_0[0][3] = 2;
    s_0[1][0] = 3;
    s_0[1][1] = 2;
    s_0[1][2] = 1;
    s_0[1][3] = 0;
    s_0[2][0] = 0;
    s_0[2][1] = 2;
    s_0[2][2] = 1;
    s_0[2][3] = 3;
    s_0[3][0] = 3;
    s_0[3][1] = 1;
    s_0[3][2] = 3; 
    s_0[3][3] = 2;
    
    s_1[0][0] = 0;
    s_1[0][1] = 1;
    s_1[0][2] = 2;
    s_1[0][3] = 3;
    s_1[1][0] = 2;
    s_1[1][1] = 0;
    s_1[1][2] = 1;
    s_1[1][3] = 3;
    s_1[2][0] = 3;
    s_1[2][1] = 0;
    s_1[2][2] = 1;
    s_1[2][3] = 0; 
    s_1[3][0] = 2;
    s_1[3][1] = 1;
    s_1[3][2] = 0; 
    s_1[3][3] = 3;
    
    // might move the above section out to encrypt function to reduce overhead
    // or make a global <--- tho this might be bad
    
    int expanded = f_expand(half);
    int xor_val = expanded^key;
    
    // bitwise AND selects right half of xor'd value (00001111)
    int mask = 15; // 00001111
    int right = mask & xor_val;
    
    // shifting up 4 makes bitwise AND select left half of xor'd value (11110000)
    mask = mask << 4;
    int left = mask & xor_val;
    left = left >> 4; // shifting so it is in expected bounds for bit_select
    
    int left_result = bit_select(s_0, left);
    int right_result = bit_select(s_1, right);
    /*
    for(i = 0; i<4; i++)
    {
        free(s_0[i]);
        free(s_1[i]);
    }
    free(s_0);
    free(s_1);
    */
    left_result = left_result << 2;
    return half_P4_perm(left_result + right_result);
}

//----------------------------- ENCRYPTION AND DECRYPTION ------------------------

int encrypt(int plain_text, int key) 
{
    int init_perm = plain_text_init_perm(plain_text);
    
    // mask used to split permuted plaintext into halves
    int mask = 240; // 11110000
    int left = mask & init_perm; 
    mask = mask >> 4;
    int right = mask & init_perm;
    left = left >> 4;
    
    // obtain each stages keys
    int k1, k2;
    get_keys(&k1, &k2, key);
    
    // these calculate the resulting halves, per the documentation
    int right_final = left ^ f(right, k1);
    int left_final = right ^ f(right_final, k2);
    
    // moving left_final up 4 so they can be added for the final permutation
    left_final = left_final << 4;
    return inverse_init_perm(left_final+right_final);
}

int decrypt(int cipher, int key)
{
    int init_perm = plain_text_init_perm(cipher);
    
    // mask used to split permuted plaintext into halves
    int mask = 240; // 11110000
    int left = mask & init_perm;
    mask = mask >> 4;
    int right = mask & init_perm;
    left = left >> 4;
    
    // obtain each stages keys
    int k1, k2;
    get_keys(&k1, &k2, key);
    
    // these calculate the resulting halves, per the documentation
    int right_final = left ^ f(right, k2);
    int left_final = right ^ f(right_final, k1);
    
    // moving left_final up 4 so they can be added for the final permutation
    left_final = left_final << 4;
    return inverse_init_perm(left_final+right_final);
}
