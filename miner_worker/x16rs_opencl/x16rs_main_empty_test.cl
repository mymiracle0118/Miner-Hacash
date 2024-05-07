


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

    // 空函数 用来做编译测试
    int num = 0;
    for(int i=0; i<10000; i++) {
        num += 1;
    }

}