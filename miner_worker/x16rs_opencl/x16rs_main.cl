
#ifndef X16RX_MAIN_CL
#define X16RX_MAIN_CL

#include "util.cl"
#include "sha3_256.cl"
#include "x16rs.cl"

void hash_x16rs_choice_step(hash_t* stephash){

    uint8_t algo = stephash->h4[7] % 16;

    if(algo == 0){ hash_x16rs_func_0 ( stephash ); }
    if(algo == 1){ hash_x16rs_func_1 ( stephash ); }
    if(algo == 2){ hash_x16rs_func_2 ( stephash ); }
    if(algo == 3){ hash_x16rs_func_3 ( stephash ); }
    if(algo == 4){ hash_x16rs_func_4 ( stephash ); }
    if(algo == 5){ hash_x16rs_func_5 ( stephash ); }
    if(algo == 6){ hash_x16rs_func_6 ( stephash ); }
    if(algo == 7){ hash_x16rs_func_7 ( stephash ); }
    if(algo == 8){ hash_x16rs_func_8 ( stephash ); }
    if(algo == 9){ hash_x16rs_func_9 ( stephash ); }
    if(algo == 10){ hash_x16rs_func_10 ( stephash ); }
    if(algo == 11){ hash_x16rs_func_11 ( stephash ); }
    if(algo == 12){ hash_x16rs_func_12 ( stephash ); }
    if(algo == 13){ hash_x16rs_func_13 ( stephash ); }
    if(algo == 14){ hash_x16rs_func_14 ( stephash ); }
    if(algo == 15){ hash_x16rs_func_15 ( stephash ); }
}



// diff hx
int diff_big_hash(hash_t* src, hash_t* tar) {
    for(int i=0; i<32; i++) {
        if(src->h1[i] > tar->h1[i]){
            return 1;
        }else if(src->h1[i] < tar->h1[i]){
            return 0;
        }
    }
    return 0;
}
int diff_big_hash_local(__local hash_t* src, __local hash_t* tar) {
    for(int i=0; i<32; i++) {
        if(src->h1[i] > tar->h1[i]){
            return 1;
        }else if(src->h1[i] < tar->h1[i]){
            return 0;
        }
    }
    return 0;
}
int diff_big_hash_global(__global hash_t* src, __global hash_t* tar) {
    for(int i=0; i<32; i++) {
        if(src->h1[i] > tar->h1[i]){
            return 1;
        }else if(src->h1[i] < tar->h1[i]){
            return 0;
        }
    }
    return 0;
}

// x16rs hash miner 算法 V3
__kernel void miner_do_hash_x16rs_v3(
   __constant unsigned char* target_difficulty_hash_32,
   __constant unsigned char* input_stuff_89,
   const unsigned int   x16rs_repeat, // x16rs根据区块高度执行的次数
   const unsigned int   nonce_start, // nonce开始值
   const unsigned int   item_loop, // 单次执行循环次数，建议 20 ～ 100
   __global unsigned char* global_nonces,
   __global hash_32* global_results )
{
    // group_size
    unsigned int global_id = get_global_id(0);
    unsigned int local_id = get_local_id(0);
    unsigned int group_size = get_local_size(0);
    unsigned int group_quantity = get_global_size(0) / group_size;
    // const unsigned int group_size = 64;
    // const unsigned int group_quantity = 64;
    unsigned int group_id = global_id / group_size;

    // group results
    hash_t local_results_ret;
    unsigned int local_nonces_ret;

    __local hash_32 group_results[128];
    __local unsigned int group_nonces[128];

    // global results
	// __global hash_t global_results[group_quantity];
	// __global unsigned int global_nonces[group_quantity];

    // stuff copy
    unsigned char base_stuff[89];
    for(int i=0; i<89; i++){
        base_stuff[i] = input_stuff_89[i];
    }

    // do loop
    unsigned int nonce = nonce_start + (global_id * item_loop);

    for(unsigned loop=0; loop<item_loop; loop++){

        // insert nonce
        write_nonce_to_bytes(79, base_stuff, nonce);
        /*// insert nonce
        unsigned char *nonce_ptr = &nonce;
        base_stuff[79] = nonce_ptr[3];
        base_stuff[80] = nonce_ptr[2];
        base_stuff[81] = nonce_ptr[1];
        base_stuff[82] = nonce_ptr[0];*/

        // hash results
        hash_t hxres;

        // hash 256
        sha3_256_hash(base_stuff, 89, hxres.h1);

        // hash x16rs
        for(int xr=0; xr < x16rs_repeat; xr++){
            hash_x16rs_choice_step(&hxres);
        }

        // smallest hx and nonce
        if(loop==0 || diff_big_hash(&local_results_ret, &hxres) == 1){
            local_results_ret = hxres;
            local_nonces_ret = nonce;
        }

        // next loop
        nonce = nonce + 1;
    }

    group_results[local_id] = cutout_hash_with_32(&local_results_ret);
    group_nonces[local_id] = local_nonces_ret;

    barrier(CLK_LOCAL_MEM_FENCE);

    // diff res hx & do reduction in shared memory
    unsigned int local_size = group_size;
    for(unsigned int smax = local_size >> 1; smax > 0; smax >>= 1)
    {
        if(local_id < smax) {
            if(diff_big_hash_local(&group_results[local_id], &group_results[local_id + smax]) == 1) {
                group_results[local_id] = group_results[local_id + smax];
                group_nonces[local_id] = group_nonces[local_id + smax];
            }
        }
        barrier(CLK_LOCAL_MEM_FENCE);
    }

    if(local_id == 0) {
        global_results[group_id] = group_results[0];
        // global_nonces[group_id] = group_nonces[0];
        write_nonce_to_global_bytes(group_id * 4, global_nonces, group_nonces[0]);
    }
}




// x16rs hash miner 算法 V2
__kernel void miner_do_hash_x16rs_v2(
   __global unsigned char* target_difficulty_hash_32,
   __global unsigned char* input_stuff_89,
   const unsigned int   x16rs_repeat, // x16rs根据区块高度执行的次数
   const unsigned int   nonce_start, // nonce开始值
   const unsigned int   item_loop, // 单次执行循环次数，建议 20 ～ 100
   __global unsigned char* output_nonce_4,
   __global unsigned char* output_hash_32)
{
    // miner check
    __local unsigned int global_barrier_success_nonce_value;
    global_barrier_success_nonce_value = 0;


    // nonce值
    unsigned int global_id = get_global_id(0);
    unsigned int nonce = nonce_start + (global_id * item_loop);
    unsigned char *nonce_ptr = &nonce;

    // stuff
    unsigned char base_stuff[89];
    for(int i=0; i<89; i++){
        base_stuff[i] = input_stuff_89[i];
    }

    // 哈希计算中间值
    hash_t hs0;

    for(int k=0; k<item_loop; k++){

        nonce = nonce + k;

        // 替换 nonce
        base_stuff[79] = nonce_ptr[3];
        base_stuff[80] = nonce_ptr[2];
        base_stuff[81] = nonce_ptr[1];
        base_stuff[82] = nonce_ptr[0];

        // hash x16rs
        sha3_256_hash(base_stuff, 89, hs0.h1);

        // x16rs根据区块高度执行的次数
        for(int xr=0; xr < x16rs_repeat; xr++){
            hash_x16rs_choice_step(&hs0);
        }
        // miner check
        unsigned int success;
        success = 0;

        // 判断是否挖矿成功
        for(int i=0; i<32; i++){
            unsigned char a1 = hs0.h1[i];
            unsigned char a2 = target_difficulty_hash_32[i];
            if( a1 > a2 ){ // 失败
                break;
            }else if( a1 < a2 ){ // 成功
                success = 1;
                break;
            }
        }

        // 挖矿成功，写入返回值数据
        if(success == 1){
            global_barrier_success_nonce_value = nonce; // 标记
            break; // 挖矿成功 弹出
        }

        // 继续下一轮挖矿

    }

    // 全局线程同步
    barrier(CLK_GLOBAL_MEM_FENCE);

    // 成功的线程写入返回值，写入返回值数据
    if(global_barrier_success_nonce_value == nonce){
        output_nonce_4[0] = nonce_ptr[3];
        output_nonce_4[1] = nonce_ptr[2];
        output_nonce_4[2] = nonce_ptr[1];
        output_nonce_4[3] = nonce_ptr[0];
        for(int i=0; i<32; i++){
            output_hash_32[i] = hs0.h1[i];
        }
    }


}


// x16rs hash miner 算法
__kernel void miner_do_hash_x16rs_v1(
   __global unsigned char* target_difficulty_hash_32,
   __global unsigned char* input_stuff_89,
   const unsigned int   base_start,
   const unsigned int   loop_num, // 循环次数
   __global unsigned char* output_nonce_4,
   __global unsigned char* output_hash_32)
{

    // miner check
    __local unsigned int success_nonce_value;
    success_nonce_value = 0;

    // 字段
    unsigned int global_id = get_global_id(0);
    unsigned int base_loop = global_id * loop_num;
    unsigned int nonce = base_start + base_loop;
    unsigned char *nonce_ptr = &nonce;

    // printf("global_id:%d, base_start:%d, base_loop:%d, nonce:%d\n", global_id, base_start, base_loop, nonce);

    // stuff
    unsigned char base_stuff[89];
    for(int i=0; i<89; i++){
        base_stuff[i] = input_stuff_89[i];
    }

    // 循环计算
    for(int n=0; n<loop_num; n++){

        nonce += 1;

        base_stuff[79] = nonce_ptr[3];
        base_stuff[80] = nonce_ptr[2];
        base_stuff[81] = nonce_ptr[1];
        base_stuff[82] = nonce_ptr[0];

        // hash x16rs
        hash_t hs0;
        sha3_256_hash(base_stuff, 89, hs0.h1);

        hash_x16rs_choice_step(&hs0);

        // output_nonce_4[0] = 0;
        // output_nonce_4[1] = 0;
        // output_nonce_4[2] = 0;
        // output_nonce_4[3] = 0;

        // printf("STEP_GLOBAL_LOCAL global_id:[%d] , nonce:[%d] \n", global_id, nonce);

        // 同步
        // barrier(CLK_GLOBAL_MEM_FENCE);

        if(success_nonce_value != 0){
            // printf("nonce_value is be set global_id:%d, base_start:%d, base_loop:%d, loop:%d break\n", global_id, base_start, base_loop, n);
            break; // 挖矿完成，退出
        }

        for(int i=0; i<32; i++){
            unsigned char a1 = hs0.h1[i];
            unsigned char a2 = target_difficulty_hash_32[i];
            if( a1 > a2 ){
                break;
            }else if( a1 < a2 ){
                success_nonce_value = nonce;
                break;
            }
        }

        // 同步
        // barrier(CLK_GLOBAL_MEM_FENCE);

        // copy set
        if(success_nonce_value == nonce){

            
            // printf("success_nonce_value ==  base_start:%d, base_loop:%d, nonce:%d[%d,%d,%d,%d], global_id:%d\n",
            //     base_start,
            //     base_loop,
            //     success_nonce_value, 
            //     nonce_ptr[0],
            //     nonce_ptr[1],
            //     nonce_ptr[2],
            //     nonce_ptr[3],
            //     global_id);

            
            // printf("success_output_hash_32 [%d,%d,%d,%d,%d,%d,%d,%d...]\n", 
            //     hs0.h1[0],
            //     hs0.h1[1],
            //     hs0.h1[2],
            //     hs0.h1[3],
            //     hs0.h1[4],
            //     hs0.h1[5],
            //     hs0.h1[6],
            //     hs0.h1[7]
            //     );
            

            output_nonce_4[0] = nonce_ptr[3];
            output_nonce_4[1] = nonce_ptr[2];
            output_nonce_4[2] = nonce_ptr[1];
            output_nonce_4[3] = nonce_ptr[0];

            for(int i=0; i<32; i++){
                output_hash_32[i] = hs0.h1[i];
            }

            // 确定完成
            break;

        }

    }

    // barrier(CLK_GLOBAL_MEM_FENCE);
    

}




/*




// x16rs hash 算法
__kernel void hash_x16rs(
   __global unsigned char* input,
   __global unsigned char* output)
{
    ////////////////////////////////////
    hash_t hhh;
    // hash_x16rs_func_0 (&hhh ); 
    // hash_x16rs_func_1 (&hhh ); 
    // hash_x16rs_func_2 (&hhh ); 
    // hash_x16rs_func_3 (&hhh ); 
    // hash_x16rs_func_4 (&hhh ); 
    // hash_x16rs_func_5 (&hhh ); 
    // hash_x16rs_func_6 (&hhh ); 
    // hash_x16rs_func_7 (&hhh ); 
    // hash_x16rs_func_8 (&hhh ); 
    // hash_x16rs_func_9 (&hhh ); 
    // hash_x16rs_func_10 (&hhh ); 
    // hash_x16rs_func_11 (&hhh ); 
    // hash_x16rs_func_12 (&hhh ); 
    // hash_x16rs_func_13 (&hhh ); 
    // hash_x16rs_func_14 (&hhh ); 
    // hash_x16rs_func_15 (&hhh ); 
    ////////////////////////////////////

    hash_t hsobj ;
    for(int i = 0; i < 32; i++){
        hsobj.h1[i] = input[i];
    }

    // 计算
    // for(int i=0; i<1; i++){
    hash_x16rs_choice_step(&hsobj);
    // }

    // 结果
    for(int i=0; i<32; i++){
        output[i] = hsobj.h1[i];
    }

}




///////////////////////////////////////////////////////////



// sha3 hash 算法
__kernel void hash_sha3(
   __global unsigned char* input,
   const unsigned int insize,
   __global unsigned char* output)
{
    hash_t hs0;
    for(int i = 0; i < insize; i++)
        hs0.h1[i] = input[i];

    sha3_256_hash(hs0.h1, insize, hs0.h1);

    // hash_x16rs_choice_step(hs0.h1);

    // 结果
    for(int i=0; i<32; i++){
        output[i] = hs0.h1[i];
    }


}


//////////////////////////////////////////////////////////////////////////





// x16rs hash 算法测试
__kernel void test_hash_x16rs(
   __global unsigned char* input,
   __global unsigned char* output)
{
    hash_t hs0 ;
    hash_t hs1 ;
    hash_t hs2 ;
    hash_t hs3 ;
    hash_t hs4 ;
    hash_t hs5 ;
    hash_t hs6 ;
    hash_t hs7 ;
    hash_t hs8 ;
    hash_t hs9 ;
    hash_t hs10;
    hash_t hs11;
    hash_t hs12;
    hash_t hs13;
    hash_t hs14;
    hash_t hs15;

    for(int i = 0; i < 32; i++)
        hs0.h1[i] = input[i];



    hash_t hhh;
    hash_x16rs_func_0 (&hhh ); 
    hash_x16rs_func_1 (&hhh ); 
    hash_x16rs_func_2 (&hhh ); 
    hash_x16rs_func_3 (&hhh ); 
    hash_x16rs_func_4 (&hhh ); 
    hash_x16rs_func_5 (&hhh ); 
    hash_x16rs_func_6 (&hhh ); 
    hash_x16rs_func_7 (&hhh ); 
    hash_x16rs_func_8 (&hhh ); 
    hash_x16rs_func_9 (&hhh ); 
    hash_x16rs_func_10 (&hhh ); 
    hash_x16rs_func_11 (&hhh ); 
    hash_x16rs_func_12 (&hhh ); 
    hash_x16rs_func_13 (&hhh ); 
    hash_x16rs_func_14 (&hhh ); 
    hash_x16rs_func_15 (&hhh ); 




    hash_x16rs_func_0 (&hs0 ); 
    for(int i = 0; i < 32; i++) hs1 .h1[i] = hs0 .h1[i];
    hash_x16rs_func_1 (&hs1 ); 
    for(int i = 0; i < 32; i++) hs2 .h1[i] = hs1 .h1[i];
    hash_x16rs_func_2 (&hs2 ); 
    for(int i = 0; i < 32; i++) hs3 .h1[i] = hs2 .h1[i];
    hash_x16rs_func_3 (&hs3 ); 
    for(int i = 0; i < 32; i++) hs4 .h1[i] = hs3 .h1[i];
    hash_x16rs_func_4 (&hs4 ); 
    for(int i = 0; i < 32; i++) hs5 .h1[i] = hs4 .h1[i];
    hash_x16rs_func_5 (&hs5 ); 
    for(int i = 0; i < 32; i++) hs6 .h1[i] = hs5 .h1[i];
    hash_x16rs_func_6 (&hs6 ); 
    for(int i = 0; i < 32; i++) hs7 .h1[i] = hs6 .h1[i];
    hash_x16rs_func_7 (&hs7 ); 
    for(int i = 0; i < 32; i++) hs8 .h1[i] = hs7 .h1[i];
    hash_x16rs_func_8 (&hs8 ); 
    for(int i = 0; i < 32; i++) hs9 .h1[i] = hs8 .h1[i];
    hash_x16rs_func_9 (&hs9 ); 
    for(int i = 0; i < 32; i++) hs10.h1[i] = hs9 .h1[i];
    hash_x16rs_func_10(&hs10); 
    for(int i = 0; i < 32; i++) hs11.h1[i] = hs10.h1[i];
    hash_x16rs_func_11(&hs11); 
    for(int i = 0; i < 32; i++) hs12.h1[i] = hs11.h1[i];
    hash_x16rs_func_12(&hs12); 
    for(int i = 0; i < 32; i++) hs13.h1[i] = hs12.h1[i];
    hash_x16rs_func_13(&hs13); 
    for(int i = 0; i < 32; i++) hs14.h1[i] = hs13.h1[i];
    hash_x16rs_func_14(&hs14); 
    for(int i = 0; i < 32; i++) hs15.h1[i] = hs14.h1[i];
    hash_x16rs_func_15(&hs15);

    // 结果
    for(int i=0; i<32; i++){
        output[i] = hs15.h1[i];
    }

}


*/




/*
// x16rs hash 算法测试
__kernel void test_hash_x16rs_old(
   __global unsigned char* input,
   __global unsigned char* output)
{

    unsigned char iiipppttt[64];

    for(int i=0; i<32; i++){
        iiipppttt[i] = input[i];
    }

    unsigned char oootttppp[64];

    unsigned char innnn[64];
    unsigned char otttt[64];

    hash_x16rs_func_0 (iiipppttt, oootttppp);
    hash_x16rs_func_1 (oootttppp, oootttppp);
    hash_x16rs_func_2 (oootttppp, oootttppp);
    hash_x16rs_func_3 (oootttppp, oootttppp);
    hash_x16rs_func_4 (oootttppp, oootttppp);
    hash_x16rs_func_5 (oootttppp, oootttppp);
    // hash_x16rs_func_6 (oootttppp, oootttppp);
    // hash_x16rs_func_7 (oootttppp, oootttppp);
    // hash_x16rs_func_8 (oootttppp, oootttppp);
    // hash_x16rs_func_9 (oootttppp, oootttppp);
    // hash_x16rs_func_10(oootttppp, oootttppp);
    hash_x16rs_func_11(oootttppp, oootttppp);
    hash_x16rs_func_12(oootttppp, oootttppp);
    hash_x16rs_func_13(oootttppp, oootttppp);
    hash_x16rs_func_14(oootttppp, oootttppp);
    hash_x16rs_func_15(oootttppp, oootttppp);
    
    for(int i=0; i<32; i++){
        output[i] = oootttppp[i];
    }

}

*/


/*

// 矩阵算法测试
__kernel void square(
   __global float* input,
   __global float* output,
   const unsigned int count)
{
   int i = get_global_id(0);
   if(i < count)
       output[i] = input[i] * input[i];
}

*/








#endif // X16RX_MAIN_CL
