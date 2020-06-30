/*******************************************************************************
*   Libonomy Wallet
*   (c) 2019 Swirlds
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "os.h"
#include "cx.h"

#include "os_io_seproxyhal.h"
#include "glyphs.h"
#include "util.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "Libonomy.pb.h"

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

static unsigned int current_text_pos; // parsing cursor in the text to display

// UI currently displayed
enum UI_STATE { UI_IDLE, UI_TEXT, UI_APPROVAL };

enum UI_STATE uiState;

ux_state_t ux;

uint32_t set_result_get_public_key(void);
unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_approve(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_deny(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e);
unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e);

static void ui_idle(void);
static unsigned char display_text_part(void);
static void ui_text(void);
static void ui_approval(void);

#define MAX_CHARS_PER_LINE 49
#define DEFAULT_FONT BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_LEFT
#define TEXT_HEIGHT 15
#define TEXT_SPACE 4

#define CLA 0xE0
#define INS_GET_PUBLIC_KEY 0x02
#define INS_SIGN 0x04
#define INS_GET_APP_CONFIGURATION 0x06
#define P1_CONFIRM 0x01
#define P1_NON_CONFIRM 0x00
#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE 0x01
#define P1_FIRST 0x00
#define P1_MORE 0x01
#define P1_LAST 0x80
#define P2_SECP256K1 0x40
#define P2_ED25519 0x80

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5

#define MAX_RAW_TX 512
#define MAX_BIP32_PATH 10
#define MAX_MEMO_SIZE 128

typedef struct publicKeyContext_t {
    uint8_t publicKey[PUBLIC_KEY_SIZE];
} publicKeyContext_t;

typedef struct transactionContext_t {
    cx_curve_t curve;
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t rawTx[MAX_RAW_TX];
    uint32_t rawTxLength;
} transactionContext_t;

union {
    publicKeyContext_t publicKeyContext;
    transactionContext_t transactionContext;
} tmpCtx;

TransactionBody *transactionBody;
volatile char fullAddress[68];
bagl_element_t tmp_element;
// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;

static char lineBuffer[50];

#ifdef TARGET_NANOS

const ux_menu_entry_t menu_main[];

const ux_menu_entry_t menu_about[] = {
    {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
    {menu_main, NULL, 2, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_main[] = {
    {NULL, NULL, 0, &C_icon_libonomy, "Use wallet to", "view accounts", 33, 12},
    {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
    {NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
    UX_MENU_END};

const bagl_element_t ui_address_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_ICON                           , 0x01,  31,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_EYE_BADGE  }, NULL, 0, 0, 0,
    // NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "public key",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Public key",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
     (char *)fullAddress,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_address_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 2:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            }
        }
        return display;
    }
    return 1;
}

unsigned int ui_address_nanos_button(unsigned int button_mask,
                                     unsigned int button_mask_counter);

const char * const ui_approval_transfer[] = {"Verify","To","Amount","Fees"};
volatile char line2[50];

static const bagl_element_t bagl_ui_approval_nanos[] = {
    // {
    //     {type, userid, x, y, width, height, stroke, radius, fill, fgcolor,
    //      bgcolor, font_id, icon_id},
    //     text,
    //     touch_area_brim,
    //     overfgcolor,
    //     overbgcolor,
    //     tap,
    //     out,
    //     over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000,
         0xFFFFFF, 0, 0},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x02, 0, 12, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Sign message",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CROSS},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CHECK},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
};

static unsigned int
bagl_ui_approval_nanos_button(unsigned int button_mask,
                              unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        io_seproxyhal_touch_approve(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_deny(NULL);
        break;
    }
    return 0;
}

static const bagl_element_t bagl_ui_text_review_nanos[] = {
    // {
    //     {type, userid, x, y, width, height, stroke, radius, fill, fgcolor,
    //      bgcolor, font_id, icon_id},
    //     text,
    //     touch_area_brim,
    //     overfgcolor,
    //     overbgcolor,
    //     tap,
    //     out,
    //     over,
    // },
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000,
         0xFFFFFF, 0, 0},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CROSS},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
         BAGL_GLYPH_ICON_CHECK},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x02, 0, 12, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x03, 23, 26, 82, 11, 0x80 | 10, 0, 0, 0xFFFFFF,
         0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
};

static unsigned int
bagl_ui_text_review_nanos_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        //if (!display_text_part()) {
            ui_approval();
        //} else {
        //    UX_REDISPLAY();
       // }
        break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        io_seproxyhal_touch_deny(NULL);
        break;
    }
    return 0;
}

#endif

unsigned int io_seproxyhal_touch_exit(const bagl_element_t *e) {
    // Go back to the dashboard
    os_sched_exit(0);
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_ok(const bagl_element_t *e) {
    uint32_t tx = set_result_get_public_key();
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_address_cancel(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

#if defined(TARGET_NANOS)
unsigned int ui_address_nanos_button(unsigned int button_mask,
                                     unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // CANCEL
        io_seproxyhal_touch_address_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // OK
        io_seproxyhal_touch_address_ok(NULL);
        break;
    }
    }
    return 0;
}
#endif // #if defined(TARGET_NANOS)

unsigned int io_seproxyhal_touch_approve(const bagl_element_t *e) {
    uint8_t privateKeyData[64];
    unsigned char finalhash[32];
    cx_sha256_t localHash;
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;
    
    if(tmpCtx.transactionContext.curve == CX_CURVE_Ed25519){
        os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10, CX_CURVE_Ed25519, tmpCtx.transactionContext.bip32Path, 
        tmpCtx.transactionContext.pathLength, privateKeyData, NULL, NULL, 0);
    }
    else {
        os_perso_derive_node_bip32(CX_CURVE_256K1, tmpCtx.transactionContext.bip32Path, 
        tmpCtx.transactionContext.pathLength, privateKeyData, NULL);
    }

    cx_ecfp_init_private_key(tmpCtx.transactionContext.curve, privateKeyData, 32, &privateKey);
    os_memset(privateKeyData, 0, sizeof(privateKeyData));
    
    if (tmpCtx.transactionContext.curve == CX_CURVE_256K1) {
        cx_sha256_init(&localHash);
        cx_hash(&localHash.header, CX_LAST, tmpCtx.transactionContext.rawTx, tmpCtx.transactionContext.rawTxLength, finalhash);
#if CX_APILEVEL >= 8
        tx = cx_ecdsa_sign(&privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA256, finalhash, sizeof(finalhash), G_io_apdu_buffer, NULL);
#else        
        tx = cx_ecdsa_sign(&privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA256, finalhash, sizeof(finalhash), G_io_apdu_buffer);
        G_io_apdu_buffer[0] = 0x30;
#endif        
    } else {
#if CX_APILEVEL >= 8
        tx = cx_eddsa_sign(&privateKey, CX_LAST, CX_SHA512, tmpCtx.transactionContext.rawTx, tmpCtx.transactionContext.rawTxLength, NULL, 0, G_io_apdu_buffer, NULL);
#else        
        tx = cx_eddsa_sign(&privateKey, NULL, CX_LAST, CX_SHA512, tmpCtx.transactionContext.rawTx, tmpCtx.transactionContext.rawTxLength, G_io_apdu_buffer);
#endif        
    }

    os_memset(&privateKey, 0, sizeof(privateKey));
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned int io_seproxyhal_touch_deny(const bagl_element_t *e) {
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}
uint32_t set_result_get_public_key() {
    os_memmove(G_io_apdu_buffer, tmpCtx.publicKeyContext.publicKey, PUBLIC_KEY_SIZE);
    return PUBLIC_KEY_SIZE;
}
void handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer,
                        uint16_t dataLength, volatile unsigned int *flags,
                        volatile unsigned int *tx) {
    UNUSED(dataLength);
    uint8_t privateKeyData[64];
    uint32_t bip32Path[MAX_BIP32_PATH];
    size_t i;
    uint8_t bip32PathLength = *(dataBuffer++);
    cx_ecfp_public_key_t publicKey;
    cx_ecfp_private_key_t privateKey;
    cx_curve_t curve;
    if ((bip32PathLength < 0x01) || (bip32PathLength > MAX_BIP32_PATH)) {
        PRINTF("Invalid path\n");
        THROW(0x6a80);
    }
    if (((p2 & P2_SECP256K1) == 0) && ((p2 & P2_ED25519) == 0)) {
        THROW(0x6B02);
    }
    if (((p2 & P2_SECP256K1) != 0) && ((p2 & P2_ED25519) != 0)) {
        THROW(0x6B03);
    }
    curve = (((p2 & P2_ED25519) != 0) ? CX_CURVE_Ed25519 : CX_CURVE_256K1);

    for (i = 0; i < bip32PathLength; i++) {
        bip32Path[i] = (dataBuffer[0] << 24) | (dataBuffer[1] << 16) |
                       (dataBuffer[2] << 8) | (dataBuffer[3]);
        dataBuffer += 4;
    }
    
    if (curve == CX_CURVE_Ed25519) {
        os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10, CX_CURVE_Ed25519, bip32Path, bip32PathLength, privateKeyData, NULL, (unsigned char*) "ed25519 seed", 12);
    } else {
        os_perso_derive_node_bip32(CX_CURVE_SECP256K1, bip32Path, bip32PathLength, privateKeyData, NULL);
    }

    cx_ecfp_init_private_key(curve, privateKeyData, PUBLIC_KEY_SIZE, &privateKey);
    cx_ecfp_generate_pair(curve, &publicKey,
                          &privateKey, 1);
    extract_public_key(publicKey,tmpCtx.publicKeyContext.publicKey);
    char pub_hex[65];
    buffer_to_hex(tmpCtx.publicKeyContext.publicKey, pub_hex, PUBLIC_KEY_SIZE);
    PRINTF("pub_hex=%s\n", pub_hex);
    PRINTF("p1=%d\n",p1);
    os_memset(&publicKey, 0, sizeof(publicKey));
    os_memset(&privateKey, 0, sizeof(privateKey));
    os_memset(privateKeyData, 0, sizeof(privateKeyData));
    
    if (p1 == P1_NON_CONFIRM) {
        *tx = set_result_get_public_key();
        THROW(0x9000);
    } else {
        os_memset(fullAddress, 0, sizeof(fullAddress));
        os_memmove((void *)fullAddress, pub_hex, 64);

// prepare for a UI based reply
#if defined(TARGET_NANOS)
        ux_step = 0;
        ux_step_count = 2;
        UX_DISPLAY(ui_address_nanos, ui_address_prepro);
#endif // #if TARGET

        *flags |= IO_ASYNCH_REPLY;
    }
}
void handleGetAppConfiguration(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                               uint16_t dataLength,
                               volatile unsigned int *flags,
                               volatile unsigned int *tx) {
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(workBuffer);
    UNUSED(dataLength);
    UNUSED(flags);
    G_io_apdu_buffer[0] = 0x00;
    G_io_apdu_buffer[1] = LEDGER_MAJOR_VERSION;
    G_io_apdu_buffer[2] = LEDGER_MINOR_VERSION;
    G_io_apdu_buffer[3] = LEDGER_PATCH_VERSION;
    *tx = 4;
    THROW(0x9000);
}
bool parseTx(uint8_t *rawTx, uint32_t rawTxLength, TransactionBody *messageBody) {
    pb_istream_t streamBody = pb_istream_from_buffer(rawTx, rawTxLength);
                        
    bool status = pb_decode(&streamBody, TransactionBody_fields, messageBody);
    /* Check for errors... */
    if (!status){
        PRINTF("Decoding body failed: %s\n", PB_GET_ERROR(&streamBody));
    }

    //curently only transfer transaction supported

    // check for trnsaction type of data field
    // if (messageBody->which_data == TransactionBody_cryptoCreateAccount_tag) {
    //     // create account transaction
    //     char result_hex[17];
    //     PRINTF("Create account transaction\n");
    //     uint64_to_hex_proper_endian(messageBody->transactionID.accountID.accountNum, result_hex);
    //     PRINTF("messageBody.transactionID.accountID.accountNum: %s \n", result_hex);
    //     uint64_to_hex_proper_endian(messageBody->data.cryptoCreateAccount.initialBalance, result_hex);
    //     PRINTF("messageBody.data.cryptoCreateAccount.initialBalance: %s \n", result_hex);
    //     PRINTF("messageBody.memo: %s\n", messageBody->memo);
    // } else if (messageBody->which_data == TransactionBody_cryptoUpdateAccount_tag) {
    //     // update account transaction
    //     char result_hex[17];
    //     PRINTF("Update account transaction\n");
    //     uint64_to_hex_proper_endian(messageBody->transactionID.accountID.accountNum, result_hex);
    //     PRINTF("messageBody.transactionID.accountID.accountNum: %s \n", result_hex);
    //     uint64_to_hex_proper_endian(messageBody->data.cryptoUpdateAccount.autoRenewPeriod.seconds, result_hex);
    //     PRINTF("messageBody.data.cryptoUpdateAccount.autoRenewPeriod.seconds: %s \n", result_hex);
    //     PRINTF("messageBody.memo: %s\n", messageBody->memo);
    // } else if (messageBody->which_data == TransactionBody_cryptoTransfer_tag) {
    if (messageBody->which_data == TransactionBody_cryptoTransfer_tag) {
        // crypto transfer transaction
        char result_hex[17];
        PRINTF("Transfer transaction\n");
        uint64_to_hex_proper_endian(messageBody->transactionID.accountID.accountNum, result_hex);
        PRINTF("messageBody.transactionID.accountID.accountNum: %s \n", result_hex);
        PRINTF("messageBody.memo: %s\n", messageBody->memo);
        int64_to_hex_proper_endian(messageBody->data.cryptoTransfer.transfers.accountAmounts[0].amount, result_hex);
        PRINTF("messageBody.data.cryptoTransfer.transfers.accountAmounts[0].amount %s\n",result_hex);
        int64_to_hex_proper_endian(messageBody->data.cryptoTransfer.transfers.accountAmounts[1].amount, result_hex);
        PRINTF("messageBody.data.cryptoTransfer.transfers.accountAmounts[1].amount %s\n",result_hex);
    } else {
        THROW(0x6B04);
    }
    return status;
}
void handleSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer,
                uint16_t dataLength, volatile unsigned int *flags,
                volatile unsigned int *tx) {
    UNUSED(tx);
    uint32_t i;
    bool last = (p1 & P1_LAST);
    p1 &= 0x7F;

    if (p1 == P1_FIRST) {
        tmpCtx.transactionContext.pathLength = workBuffer[0];
        if ((tmpCtx.transactionContext.pathLength < 0x01) ||
            (tmpCtx.transactionContext.pathLength > MAX_BIP32_PATH)) {
            PRINTF("Invalid path\n");
            THROW(0x6a80);
        }
        workBuffer++;
        dataLength--;
        for (i = 0; i < tmpCtx.transactionContext.pathLength; i++) {
            tmpCtx.transactionContext.bip32Path[i] =
                (workBuffer[0] << 24) | (workBuffer[1] << 16) |
                (workBuffer[2] << 8) | (workBuffer[3]);
            workBuffer += 4;
            dataLength -= 4;
        }
        if (((p2 & P2_SECP256K1) == 0) && ((p2 & P2_ED25519) == 0)) {
            THROW(0x6B00);
        }
        if (((p2 & P2_SECP256K1) != 0) && ((p2 & P2_ED25519) != 0)) {
            THROW(0x6B00);
        }
        tmpCtx.transactionContext.curve =
            (((p2 & P2_ED25519) != 0) ? CX_CURVE_Ed25519 : CX_CURVE_256K1);
    } else 
    if (p1 != P1_MORE) {
        THROW(0x6B00);
    }

    if (p1 == P1_FIRST) {
        if (dataLength > MAX_RAW_TX) {
            THROW(0x6A80);
        }
        tmpCtx.transactionContext.rawTxLength = dataLength;
        os_memmove(tmpCtx.transactionContext.rawTx, workBuffer, dataLength);
    }
    else
    if (p1 == P1_MORE) {
        if ((tmpCtx.transactionContext.rawTxLength + dataLength) > MAX_RAW_TX) {
            THROW(0x6A80);
        }
        os_memmove(tmpCtx.transactionContext.rawTx + tmpCtx.transactionContext.rawTxLength, workBuffer, dataLength);
        tmpCtx.transactionContext.rawTxLength += dataLength;
    }

    if (!last) {
        THROW(0x9000);
    }
    TransactionBody messageBody = TransactionBody_init_default;
    if (!parseTx(tmpCtx.transactionContext.rawTx, tmpCtx.transactionContext.rawTxLength, &messageBody)) {        
        THROW(0x6A80);
    }
    transactionBody = &messageBody;
    
    current_text_pos = 0;
    
    ux_step = 0;
    ux_step_count = 4; 
    display_text_part();
    ui_text();

    *flags |= IO_ASYNCH_REPLY;
}
void handleApdu(volatile unsigned int *flags, volatile unsigned int *tx) {
    unsigned short sw = 0;

    BEGIN_TRY {
        TRY {
            if (G_io_apdu_buffer[0] != CLA) {
                THROW(0x6E00);
            }

            switch (G_io_apdu_buffer[1]) {
            case INS_SIGN: 
                handleSign(G_io_apdu_buffer[OFFSET_P1],
                           G_io_apdu_buffer[OFFSET_P2],
                           G_io_apdu_buffer + OFFSET_CDATA,
                           G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;

            case INS_GET_PUBLIC_KEY: 
                handleGetPublicKey(G_io_apdu_buffer[OFFSET_P1],
                                   G_io_apdu_buffer[OFFSET_P2],
                                   G_io_apdu_buffer + OFFSET_CDATA,
                                   G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;
            
            case INS_GET_APP_CONFIGURATION:
                handleGetAppConfiguration(
                    G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2],
                    G_io_apdu_buffer + OFFSET_CDATA,
                    G_io_apdu_buffer[OFFSET_LC], flags, tx);
                break;

            default:
                THROW(0x6D00);
                break;
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e) {
            switch (e & 0xF000) {
            case 0x6000:
                // Wipe the transaction context and report the exception
                sw = e;
                //os_memset(&txContent, 0, sizeof(txContent));
                break;
            case 0x9000:
                // All is well
                sw = e;
                break;
            default:
                // Internal error
                sw = 0x6800 | (e & 0x7FF);
                break;
            }
            // Unexpected exception => report
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY {
        }
    }
    END_TRY;
}
static void libonomy_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;


    // next timer callback in 500 ms
    UX_CALLBACK_SET_INTERVAL(500);

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                handleApdu(&flags, &tx);
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                case 0x6000:
                case 0x9000:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    return;
}

void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
}

// Pick the text elements to display
static unsigned char display_text_part() {
    unsigned int i;
    //WIDE char *text = (char*) G_io_apdu_buffer + 5;
    WIDE char *text = "test\0";
    if (text[current_text_pos] == '\0') {
        return 0;
    }
    i = 0;
    while ((text[current_text_pos] != 0) && (text[current_text_pos] != '\n') &&
           (i < MAX_CHARS_PER_LINE)) {
        lineBuffer[i++] = text[current_text_pos];
        current_text_pos++;
    }
    if (text[current_text_pos] == '\n') {
        current_text_pos++;
    }
    lineBuffer[i] = '\0';
    return 1;
}
unsigned short print_account(int64_t account, char *out,
                                uint32_t outlen) {
    char tmp[20];
    uint32_t numDigits = 0, i;
    int64_t base = 1;
    while (base <= account) {
        base *= 10;
        numDigits++;
    }
    if (numDigits > sizeof(tmp) - 1) {
        THROW(EXCEPTION);
    }
    base /= 10;
    for (i = 0; i < numDigits; i++) {
        tmp[i] = '0' + ((account / base) % 10);
        base /= 10;
    }
    tmp[i] = '\0';
    if (strlen(tmp) < outlen - 1) {
        strcpy(out, tmp);
    } else {
        out[0] = '\0';
    }
    return strlen(out);
}
bool adjustDecimals(char *src, uint32_t srcLength, char *target,
                    uint32_t targetLength, uint8_t decimals) {
    uint32_t startOffset;
    uint32_t lastZeroOffset = 0;
    uint32_t offset = 0;

    if ((srcLength == 1) && (*src == '0')) {
        if (targetLength < 2) {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '\0';
        return true;
    }
    if (srcLength <= decimals) {
        uint32_t delta = decimals - srcLength;
        if (targetLength < srcLength + 1 + 2 + delta) {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '.';
        for (uint32_t i = 0; i < delta; i++) {
            target[offset++] = '0';
        }
        startOffset = offset;
        for (uint32_t i = 0; i < srcLength; i++) {
            target[offset++] = src[i];
        }
        target[offset] = '\0';
    } else {
        uint32_t sourceOffset = 0;
        uint32_t delta = srcLength - decimals;
        if (targetLength < srcLength + 1 + 1) {
            return false;
        }
        while (offset < delta) {
            target[offset++] = src[sourceOffset++];
        }
        if (decimals != 0) {
            target[offset++] = '.';
        }
        startOffset = offset;
        while (sourceOffset < srcLength) {
            target[offset++] = src[sourceOffset++];
        }
        target[offset] = '\0';
    }
    for (uint32_t i = startOffset; i < offset; i++) {
        if (target[i] == '0') {
            if (lastZeroOffset == 0) {
                lastZeroOffset = i;
            }
        } else {
            lastZeroOffset = 0;
        }
    }
    if (lastZeroOffset != 0) {
        target[lastZeroOffset] = '\0';
        if (target[lastZeroOffset - 1] == '.') {
            target[lastZeroOffset - 1] = '\0';
        }
    }
    return true;
}
unsigned short print_amount(uint64_t amount, char *out,
                                uint32_t outlen) {
    char tmp[20];
    char tmp2[26];
    uint32_t numDigits = 0, i;
    uint64_t base = 1;
    while (base <= amount) {
        base *= 10;
        numDigits++;
    }
    if (numDigits > sizeof(tmp) - 1) {
        THROW(EXCEPTION);
    }
    base /= 10;
    for (i = 0; i < numDigits; i++) {
        tmp[i] = '0' + ((amount / base) % 10);
        base /= 10;
    }
    tmp[i] = '\0';
    strcpy(tmp2, "HBAR ");
    adjustDecimals(tmp, i, tmp2 + 5, 26, 8);
    if (strlen(tmp2) < outlen - 1) {
        strcpy(out, tmp2);
    } else {
        out[0] = '\0';
    }
    return strlen(out);
}
bagl_element_t*  bagl_ui_text_review_prepro(const bagl_element_t *element) {
    switch (element->component.userid)
    {
    case 0x00:
        return element;
        break;
    
    case 0x02:
        os_memmove(&tmp_element, element, sizeof(bagl_element_t));
        if(transactionBody->which_data==TransactionBody_cryptoTransfer_tag) {
            tmp_element.text=ui_approval_transfer[ux_step];
            UX_CALLBACK_SET_INTERVAL(MAX(3000, 1000 + bagl_label_roundtrip_duration_ms(&tmp_element, 7)));
        }
        return &tmp_element;
        break;
    
    case 0x03:
        os_memmove(&tmp_element, element, sizeof(bagl_element_t));
        //currenctly only one payment (two accountAmounts) supported
        if(transactionBody->data.cryptoTransfer.transfers.accountAmounts_count != 2) {
            THROW(EXCEPTION);
        }
        uint16_t accountAmountIndex = (transactionBody->data.cryptoTransfer.transfers.accountAmounts[0].amount > 0) ? 0 : 1;
        switch (ux_step)
        {
        case 0:
            //Verify transaction message
            if(transactionBody->which_data==TransactionBody_cryptoTransfer_tag) {
                tmp_element.text = "transaction";
            }
            break;
        
        case 1:
            //To account
            if(transactionBody->which_data==TransactionBody_cryptoTransfer_tag) {
                print_account(transactionBody->data.cryptoTransfer.transfers.accountAmounts[accountAmountIndex].accountID.accountNum, line2, sizeof(line2));
                tmp_element.text = line2;
            }
            break;
        
        case 2:
            //Transfer amount
            if(transactionBody->which_data==TransactionBody_cryptoTransfer_tag) {
                print_amount(transactionBody->data.cryptoTransfer.transfers.accountAmounts[accountAmountIndex].amount, line2, sizeof(line2));
                tmp_element.text = line2;
            }
            break;
        
        case 3:
            //Transaction fee
            if(transactionBody->which_data==TransactionBody_cryptoTransfer_tag) {
                print_amount(transactionBody->transactionFee, line2, sizeof(line2));
                tmp_element.text = line2;
            }
            break;
        
        default:
            break;
        }
        UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(&tmp_element, 7)));
                
        return &tmp_element;
        break;
    
    default:
        break;
    }
    return NULL;
}
static void ui_idle(void) {
    uiState = UI_IDLE;
    UX_MENU_DISPLAY(0, menu_main, NULL);
}
static void ui_text(void) {
    uiState = UI_TEXT;
    UX_DISPLAY(bagl_ui_text_review_nanos, bagl_ui_text_review_prepro);
}

static void ui_approval(void) {
    uiState = UI_APPROVAL;
    UX_DISPLAY(bagl_ui_approval_nanos, NULL);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT: // for Nano S
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        //if ((uiState == UI_TEXT) &&
        //    (os_seph_features() &
        //     SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG)) {
        //    if (!display_text_part()) {
        //        ui_approval();
        //    } else {
        //        UX_REDISPLAY();
        //    }
        //} else {
            UX_DISPLAYED_EVENT();
        //}
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        #ifdef TARGET_NANOS
            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
                // defaulty retrig very soon (will be overriden during
                // stepper_prepro)
                //UX_CALLBACK_SET_INTERVAL(500);
                ux_step = (ux_step + 1) % ux_step_count;
                UX_REDISPLAY();
            });
        #endif 
        break;

    // unknown events are acknowledged
    default:
        UX_DEFAULT_EVENT();
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    current_text_pos = 0;
    uiState = UI_IDLE;

    // ensure exception will work as planned
    os_boot();

    for (;;) {
        UX_INIT();

        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

    #ifdef LISTEN_BLE
                if (os_seph_features() &
                    SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_BLE) {
                    BLE_power(0, NULL);
                    // restart IOs
                    BLE_power(1, NULL);
                }
    #endif

                USB_power(0);
                USB_power(1);

                ui_idle();

                libonomy_main();
            }
            CATCH_OTHER(e) {
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    io_seproxyhal_touch_exit(NULL);
    return 0;
}
