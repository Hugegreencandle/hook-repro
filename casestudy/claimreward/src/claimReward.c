#include "hookapi.h"

// Macro to flip endianness for 32-bit values
#define FLIP_ENDIAN(x) ((((x) & 0xFF000000) >> 24) | \
                        (((x) & 0x00FF0000) >> 8)  | \
                        (((x) & 0x0000FF00) << 8)  | \
                        (((x) & 0x000000FF) << 24))

// ClaimReward transaction template
uint8_t ctxn[251] =
{
/* size,upto */
/* 3,    0, tt = ClaimReward      */   0x12U, 0x00U, 0x62U,
/* 5,    3  flags                 */   0x22U, 0x00U, 0x00U, 0x00U, 0x00U,
/* 5,    8, sequence              */   0x24U, 0x00U, 0x00U, 0x00U, 0x00U,
/* 6,   13, firstledgersequence   */   0x20U, 0x1AU, 0x00U, 0x00U, 0x00U, 0x00U,
/* 6,   19, lastledgersequence    */   0x20U, 0x1BU, 0x00U, 0x00U, 0x00U, 0x00U,
/* 9,   25, fee                   */   0x68U, 0x40U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
/* 35,  34, signingpubkey         */   0x73U, 0x21U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 22,  69, account               */   0x81U, 0x14U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 22,  91, issuer                */   0x84U, 0x14U, 0xB5U, 0xF7U, 0x62U, 0x79U, 0x8AU, 0x53U, 0xD5U, 0x43U, 0xA0U, 0x14U, 0xCAU, 0xF8U, 0xB2U, 0x97U, 0xCFU, 0xF8U, 0xF2U, 0xF9U, 0x37U, 0xE8U,
/* 138, 113  emit details          */  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 0,  251                        */ 
};

#define CFLS_OUT (ctxn + 15U)
#define CLLS_OUT (ctxn + 21U)
#define CFEE_OUT (ctxn + 26U)
#define CACCOUNT_OUT (ctxn + 71U)
#define CEMIT_OUT (ctxn + 113U)

#define BE_DROPS(drops)\
{\
        uint64_t drops_tmp = drops;\
        uint8_t* b = (uint8_t*)&drops;\
        *b++ = 0b01000000 + (( drops_tmp >> 56 ) & 0b00111111 );\
        *b++ = (drops_tmp >> 48) & 0xFFU;\
        *b++ = (drops_tmp >> 40) & 0xFFU;\
        *b++ = (drops_tmp >> 32) & 0xFFU;\
        *b++ = (drops_tmp >> 24) & 0xFFU;\
        *b++ = (drops_tmp >> 16) & 0xFFU;\
        *b++ = (drops_tmp >>  8) & 0xFFU;\
        *b++ = (drops_tmp >>  0) & 0xFFU;\
}

// Callback function
int64_t cbak(uint32_t reserve)
{
    accept((uint32_t)"Callback completed", 18, __LINE__);
    return 0;
}

// Main hook function using state_foreign for custom namespace
int64_t hook(uint32_t reserved)
{
    // Proceed with ClaimReward emission
    uint32_t current_ledger = ledger_seq();
    uint32_t fls = current_ledger + 1;
    uint32_t lls = fls + 4;
    
    etxn_reserve(1);
    uint8_t emithash[32];

    hook_account((uint32_t)CACCOUNT_OUT, 20);
    *((uint32_t *)(CFLS_OUT)) = FLIP_ENDIAN(fls);
    *((uint32_t *)(CLLS_OUT)) = FLIP_ENDIAN(lls);
    etxn_details((uint32_t)CEMIT_OUT, 138U);

    int64_t fee = etxn_fee_base((uint32_t)ctxn, sizeof(ctxn));
    BE_DROPS(fee);
    *((uint64_t*)(CFEE_OUT)) = fee;

    if (emit(SBUF(emithash), (uint32_t)ctxn, sizeof(ctxn)) != 32)
        rollback((uint32_t)"AutoReward: Failed to emit claim transaction.", 45, __LINE__);

    accept((uint32_t)"AutoReward: Claim emitted successfully.", 39, __LINE__);
    _g(1, 1);
    return 0;
}