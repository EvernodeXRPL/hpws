#ifndef HPWS_VISAPASS
#define HPWS_VISAPASS

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

#define __VISAPASS_SLOT_COUNT 100
#define __IP_V4 1
#define __IP_V6 2
#define CHALLENGE_SIZE 32
#define ID_SIZE 32

struct __visapass_slot
{
    uint8_t occupied;                        // 0 = vacant, 1 = occupied.
    time_t expire;                           // Epoch seconds at which the visa will expire.
    unsigned char id[ID_SIZE];               // Identifier for the slot.
    unsigned char challenge[CHALLENGE_SIZE]; // Issued visa challenge.
    bool passed;                             // Whether visa is passed.
};

static struct __visapass_slot __visapasses[__VISAPASS_SLOT_COUNT];
static int __visapass_filled_boundry = 0; // Indicates the last slot that has been touched.

/**
 * @return Pointer if found. NULL if not found/expired.
 */
struct __visapass_slot *__visapass_find(const unsigned char *id)
{
    struct __visapass_slot *found = NULL;

    for (int i = 0; i < __visapass_filled_boundry; i++)
    {
        struct __visapass_slot *slot = &__visapasses[i];
        if (slot->occupied == 1 && memcmp(slot->id, id, ID_SIZE) == 0)
        {
            found = slot;
            break;
        }
    }

    // If the slot we found has expired, clean it up.
    if (found && found->expire <= time(NULL))
    {
        found->occupied = 0; // Mark the slot as vacant.
        found = NULL;
    }

    return found;
}

// Public interface-------------------------

void visapass_pass(const unsigned char *id)
{
    struct __visapass_slot *slot = __visapass_find(id);
    if (slot)
        slot->passed = true;
}

/**
 * @return 0 if success. -1 if failure (due to all slots being filled).
 */
int visapass_add(const unsigned char *id, const uint32_t ttl_sec, const unsigned char *challenge)
{
    // Check if already exists.
    struct __visapass_slot *slot = __visapass_find(id);
    if (!slot) // If not existing, find first vacant slot.
    {
        for (int i = 0; i < __VISAPASS_SLOT_COUNT; i++)
        {
            if (__visapasses[i].occupied == 0)
            {
                slot = &__visapasses[i];
                if (__visapass_filled_boundry < i + 1)
                    __visapass_filled_boundry = i + 1;
                break;
            }
        }
    }

    if (slot)
    {
        slot->occupied = 1;
        slot->expire = time(NULL) + ttl_sec;
        slot->passed = false;
        memcpy(slot->challenge, challenge, CHALLENGE_SIZE);
        memcpy(slot->id, id, ID_SIZE);

        return 0;
    }

    return -1;
}

void visapass_remove(const unsigned char *id)
{
    struct __visapass_slot *slot = __visapass_find(id);
    if (slot)
        slot->occupied = 0;
}

bool visapass_is_passed(const unsigned char *id)
{
    struct __visapass_slot *slot = __visapass_find(id);
    return slot != NULL && slot->passed;
}

const unsigned char *visapass_get_challenge(const unsigned char *id)
{
    struct __visapass_slot *slot = __visapass_find(id);
    if (slot)
        return (const unsigned char *)slot->challenge;
    return NULL;
}

#endif