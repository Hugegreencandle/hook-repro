#include "hookapi.h"

/**
 * @field blaccid Set to binary account
 * @field blns Set to the blacklist hook namespace
 */

int64_t hook(uint32_t reserved)
{
    GUARD(1);

    // fetch the originating account ID
    uint8_t otxn_accid[20];
    if (otxn_field(otxn_accid, 20, sfAccount) != 20)
        rollback(SBUF("Firewall: Could not fetch sfAccount from originating transaction!!!"), 1);

    uint8_t blacklist_ns[32];
    int64_t prv = hook_param(SBUF(blacklist_ns), (uint32_t)"blns", 4);
    if (prv != sizeof(blacklist_ns))
    {
        TRACEVAR(prv);
        rollback(SBUF("Firewall: \"blns\" parameter missing"), 5);
    }

    uint8_t blacklist_accid[32];
    prv = hook_param(SBUF(blacklist_accid), (uint32_t)"blaccid", 7);
    if (prv < 20)
    {
        TRACEVAR(prv);
        rollback(SBUF("Firewall: \"blaccid\" parameter missing"), 10);
    }

    // look up the account ID in the foreign state (blacklist account's hook state)
    uint8_t blacklist_status[1] = { 0 };
    int64_t lookup = state_foreign(SBUF(blacklist_status), SBUF(otxn_accid), SBUF(blacklist_ns), blacklist_accid, 20);
    if (lookup == INVALID_ACCOUNT)
        trace(SBUF("Firewall: Warning specified blacklist account does not exist."), 0, 0, 0);

    if (blacklist_status[0] == 0)
        accept(SBUF("Firewall: Allowing transaction."), 0);

    rollback(SBUF("Firewall: Blocking transaction from blacklisted account."), 1);

    return 0;
}

