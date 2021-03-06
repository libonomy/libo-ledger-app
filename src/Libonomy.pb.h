/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.0-dev at Wed May  8 15:33:58 2019. */

#ifndef PB_CREATEACCOUNT_PB_H_INCLUDED
#define PB_CREATEACCOUNT_PB_H_INCLUDED
#include <pb.h>

#include "wrappers.pb.h"

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _LibonomyFunctionality {
    LibonomyFunctionality_NONE = 0,
    LibonomyFunctionality_CryptoTransfer = 1,
    LibonomyFunctionality_CryptoUpdate = 2,
    LibonomyFunctionality_CryptoDelete = 3,
    LibonomyFunctionality_CryptoAddClaim = 4,
    LibonomyFunctionality_CryptoDeleteClaim = 5,
    LibonomyFunctionality_ContractCall = 6,
    LibonomyFunctionality_ContractCreate = 7,
    LibonomyFunctionality_ContractUpdate = 8,
    LibonomyFunctionality_FileCreate = 9,
    LibonomyFunctionality_FileAppend = 10,
    LibonomyFunctionality_FileUpdate = 11,
    LibonomyFunctionality_FileDelete = 12,
    LibonomyFunctionality_CryptoGetAccountBalance = 13,
    LibonomyFunctionality_CryptoGetAccountRecords = 14,
    LibonomyFunctionality_CryptoGetInfo = 15,
    LibonomyFunctionality_ContractCallLocal = 16,
    LibonomyFunctionality_ContractGetInfo = 17,
    LibonomyFunctionality_ContractGetBytecode = 18,
    LibonomyFunctionality_GetBySolidityID = 19,
    LibonomyFunctionality_GetByKey = 20,
    LibonomyFunctionality_CryptoGetClaim = 21,
    LibonomyFunctionality_CryptoGetStakers = 22,
    LibonomyFunctionality_FileGetContents = 23,
    LibonomyFunctionality_FileGetInfo = 24,
    LibonomyFunctionality_TransactionGetRecord = 25,
    LibonomyFunctionality_ContractGetRecords = 26,
    LibonomyFunctionality_CryptoCreate = 27,
    LibonomyFunctionality_SystemDelete = 28,
    LibonomyFunctionality_SystemUndelete = 29,
    LibonomyFunctionality_ContractDelete = 30
} LibonomyFunctionality;
#define _LibonomyFunctionality_MIN LibonomyFunctionality_NONE
#define _LibonomyFunctionality_MAX LibonomyFunctionality_ContractDelete
#define _LibonomyFunctionality_ARRAYSIZE ((LibonomyFunctionality)(LibonomyFunctionality_ContractDelete+1))

/* Struct definitions */
typedef struct _KeyList {
    pb_callback_t keys;
/* @@protoc_insertion_point(struct:KeyList) */
} KeyList;

typedef struct _NodeAddressBook {
    pb_callback_t nodeAddress;
/* @@protoc_insertion_point(struct:NodeAddressBook) */
} NodeAddressBook;

typedef struct _SignatureList {
    pb_callback_t sigs;
/* @@protoc_insertion_point(struct:SignatureList) */
} SignatureList;

typedef struct _SignatureMap {
    pb_callback_t sigPair;
/* @@protoc_insertion_point(struct:SignatureMap) */
} SignatureMap;

typedef struct _AccountID {
    int64_t shardNum;
    int64_t realmNum;
    int64_t accountNum;
/* @@protoc_insertion_point(struct:AccountID) */
} AccountID;

typedef struct _ContractID {
    int64_t shardNum;
    int64_t realmNum;
    int64_t contractNum;
/* @@protoc_insertion_point(struct:ContractID) */
} ContractID;

typedef struct _Duration {
    int64_t seconds;
/* @@protoc_insertion_point(struct:Duration) */
} Duration;

typedef struct _FeeComponents {
    int64_t min;
    int64_t max;
    int64_t constant;
    int64_t bpt;
    int64_t vpt;
    int64_t rbs;
    int64_t sbs;
    int64_t gas;
    int64_t tv;
    int64_t bpr;
    int64_t sbpr;
/* @@protoc_insertion_point(struct:FeeComponents) */
} FeeComponents;

typedef struct _FileID {
    int64_t shardNum;
    int64_t realmNum;
    int64_t fileNum;
/* @@protoc_insertion_point(struct:FileID) */
} FileID;

typedef struct _NodeAddress {
    pb_callback_t ipAddress;
    int32_t portno;
    pb_callback_t memo;
/* @@protoc_insertion_point(struct:NodeAddress) */
} NodeAddress;

typedef struct _RealmID {
    int64_t shardNum;
    int64_t realmNum;
/* @@protoc_insertion_point(struct:RealmID) */
} RealmID;

typedef struct _ShardID {
    int64_t shardNum;
/* @@protoc_insertion_point(struct:ShardID) */
} ShardID;

typedef PB_BYTES_ARRAY_T(32) SignaturePair_contract_t;
typedef PB_BYTES_ARRAY_T(32) SignaturePair_ed25519_t;
typedef PB_BYTES_ARRAY_T(32) SignaturePair_RSA_3072_t;
typedef PB_BYTES_ARRAY_T(97) SignaturePair_ECDSA_384_t;
typedef struct _SignaturePair {
    pb_callback_t pubKeyPrefix;
    pb_size_t which_signature;
    union {
        SignaturePair_contract_t contract;
        SignaturePair_ed25519_t ed25519;
        SignaturePair_RSA_3072_t RSA_3072;
        SignaturePair_ECDSA_384_t ECDSA_384;
    } signature;
/* @@protoc_insertion_point(struct:SignaturePair) */
} SignaturePair;

typedef struct _ThresholdKey {
    uint32_t threshold;
    KeyList keys;
/* @@protoc_insertion_point(struct:ThresholdKey) */
} ThresholdKey;

typedef struct _ThresholdSignature {
    SignatureList sigs;
/* @@protoc_insertion_point(struct:ThresholdSignature) */
} ThresholdSignature;

typedef struct _Timestamp {
    int64_t seconds;
    int32_t nanos;
/* @@protoc_insertion_point(struct:Timestamp) */
} Timestamp;

typedef struct _TimestampSeconds {
    int64_t seconds;
/* @@protoc_insertion_point(struct:TimestampSeconds) */
} TimestampSeconds;

typedef struct _AccountAmount {
    AccountID accountID;
    int64_t amount;
/* @@protoc_insertion_point(struct:AccountAmount) */
} AccountAmount;

typedef struct _FeeData {
    FeeComponents nodedata;
    FeeComponents networkdata;
    FeeComponents servicedata;
/* @@protoc_insertion_point(struct:FeeData) */
} FeeData;

typedef struct _FeeSchedule {
    pb_callback_t transactionFeeSchedule;
    TimestampSeconds expiryTime;
/* @@protoc_insertion_point(struct:FeeSchedule) */
} FeeSchedule;

typedef PB_BYTES_ARRAY_T(32) Key_ed25519_t;
typedef PB_BYTES_ARRAY_T(32) Key_RSA_3072_t;
typedef PB_BYTES_ARRAY_T(97) Key_ECDSA_384_t;
typedef struct _Key {
    pb_size_t which_key;
    union {
        ContractID contractID;
        Key_ed25519_t ed25519;
        Key_RSA_3072_t RSA_3072;
        Key_ECDSA_384_t ECDSA_384;
        ThresholdKey thresholdKey;
        KeyList keyList;
    } key;
/* @@protoc_insertion_point(struct:Key) */
} Key;

typedef PB_BYTES_ARRAY_T(32) Signature_contract_t;
typedef PB_BYTES_ARRAY_T(32) Signature_ed25519_t;
typedef PB_BYTES_ARRAY_T(32) Signature_RSA_3072_t;
typedef PB_BYTES_ARRAY_T(97) Signature_ECDSA_384_t;
typedef struct _Signature {
    pb_size_t which_signature;
    union {
        Signature_contract_t contract;
        Signature_ed25519_t ed25519;
        Signature_RSA_3072_t RSA_3072;
        Signature_ECDSA_384_t ECDSA_384;
        ThresholdSignature thresholdSignature;
        SignatureList signatureList;
    } signature;
/* @@protoc_insertion_point(struct:Signature) */
} Signature;

typedef struct _TransactionID {
    Timestamp transactionValidStart;
    AccountID accountID;
/* @@protoc_insertion_point(struct:TransactionID) */
} TransactionID;

typedef struct _CryptoCreateTransactionBody {
    Key key;
    uint64_t initialBalance;
    AccountID proxyAccountID;
    uint64_t sendRecordThreshold;
    uint64_t receiveRecordThreshold;
    bool receiverSigRequired;
    Duration autoRenewPeriod;
    ShardID shardID;
    RealmID realmID;
    Key newRealmAdminKey;
/* @@protoc_insertion_point(struct:CryptoCreateTransactionBody) */
} CryptoCreateTransactionBody;

typedef struct _CryptoUpdateTransactionBody {
    AccountID accountIDToUpdate;
    Key key;
    AccountID proxyAccountID;
    int32_t proxyFraction;
    pb_size_t which_sendRecordThresholdField;
    union {
        uint64_t sendRecordThreshold;
        google_protobuf_UInt64Value sendRecordThresholdWrapper;
    } sendRecordThresholdField;
    pb_size_t which_receiveRecordThresholdField;
    union {
        uint64_t receiveRecordThreshold;
        google_protobuf_UInt64Value receiveRecordThresholdWrapper;
    } receiveRecordThresholdField;
    Duration autoRenewPeriod;
    Timestamp expirationTime;
    pb_size_t which_receiverSigRequiredField;
    union {
        bool receiverSigRequired;
        google_protobuf_BoolValue receiverSigRequiredWrapper;
    } receiverSigRequiredField;
/* @@protoc_insertion_point(struct:CryptoUpdateTransactionBody) */
} CryptoUpdateTransactionBody;

typedef struct _CurrentAndNextFeeSchedule {
    FeeSchedule currentFeeSchedule;
    FeeSchedule nextFeeSchedule;
/* @@protoc_insertion_point(struct:CurrentAndNextFeeSchedule) */
} CurrentAndNextFeeSchedule;

typedef struct _TransactionFeeSchedule {
    LibonomyFunctionality libonomyFunctionality;
    FeeData feeData;
/* @@protoc_insertion_point(struct:TransactionFeeSchedule) */
} TransactionFeeSchedule;

typedef struct _TransferList {
    pb_size_t accountAmounts_count;
    AccountAmount accountAmounts[2];
/* @@protoc_insertion_point(struct:TransferList) */
} TransferList;

typedef struct _CryptoTransferTransactionBody {
    TransferList transfers;
/* @@protoc_insertion_point(struct:CryptoTransferTransactionBody) */
} CryptoTransferTransactionBody;

typedef struct _TransactionBody {
    TransactionID transactionID;
    AccountID nodeAccountID;
    uint64_t transactionFee;
    Duration transactionValidDuration;
    bool generateRecord;
    char memo[128];
    pb_size_t which_data;
    union {
        CryptoCreateTransactionBody cryptoCreateAccount;
        CryptoTransferTransactionBody cryptoTransfer;
        CryptoUpdateTransactionBody cryptoUpdateAccount;
    } data;
/* @@protoc_insertion_point(struct:TransactionBody) */
} TransactionBody;

typedef PB_BYTES_ARRAY_T(1024) Transaction_bodyBytes_t;
typedef struct _Transaction {
    pb_size_t which_bodyData;
    union {
        TransactionBody body;
        Transaction_bodyBytes_t bodyBytes;
    } bodyData;
    SignatureList sigs;
    SignatureMap sigMap;
/* @@protoc_insertion_point(struct:Transaction) */
} Transaction;

/* Default values for struct fields */

/* Initializer values for message structs */
#define ShardID_init_default                     {0}
#define RealmID_init_default                     {0, 0}
#define AccountID_init_default                   {0, 0, 0}
#define FileID_init_default                      {0, 0, 0}
#define ContractID_init_default                  {0, 0, 0}
#define TransactionID_init_default               {Timestamp_init_default, AccountID_init_default}
#define Key_init_default                         {0, {ContractID_init_default}}
#define ThresholdKey_init_default                {0, KeyList_init_default}
#define KeyList_init_default                     {{{NULL}, NULL}}
#define Signature_init_default                   {0, {{0, {0}}}}
#define ThresholdSignature_init_default          {SignatureList_init_default}
#define SignatureList_init_default               {{{NULL}, NULL}}
#define SignaturePair_init_default               {{{NULL}, NULL}, 0, {{0, {0}}}}
#define SignatureMap_init_default                {{{NULL}, NULL}}
#define FeeComponents_init_default               {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
#define TransactionFeeSchedule_init_default      {(LibonomyFunctionality)0, FeeData_init_default}
#define FeeData_init_default                     {FeeComponents_init_default, FeeComponents_init_default, FeeComponents_init_default}
#define FeeSchedule_init_default                 {{{NULL}, NULL}, TimestampSeconds_init_default}
#define CurrentAndNextFeeSchedule_init_default   {FeeSchedule_init_default, FeeSchedule_init_default}
#define NodeAddress_init_default                 {{{NULL}, NULL}, 0, {{NULL}, NULL}}
#define NodeAddressBook_init_default             {{{NULL}, NULL}}
#define Duration_init_default                    {0}
#define Timestamp_init_default                   {0, 0}
#define TimestampSeconds_init_default            {0}
#define CryptoCreateTransactionBody_init_default {Key_init_default, 0, AccountID_init_default, 0, 0, 0, Duration_init_default, ShardID_init_default, RealmID_init_default, Key_init_default}
#define CryptoUpdateTransactionBody_init_default {AccountID_init_default, Key_init_default, AccountID_init_default, 0, 0, {0}, 0, {0}, Duration_init_default, Timestamp_init_default, 0, {0}}
#define AccountAmount_init_default               {AccountID_init_default, 0}
#define TransferList_init_default                {0, {AccountAmount_init_default, AccountAmount_init_default}}
#define CryptoTransferTransactionBody_init_default {TransferList_init_default}
#define TransactionBody_init_default             {TransactionID_init_default, AccountID_init_default, 0, Duration_init_default, 0, "", 0, {CryptoCreateTransactionBody_init_default}}
#define Transaction_init_default                 {0, {TransactionBody_init_default}, SignatureList_init_default, SignatureMap_init_default}
#define ShardID_init_zero                        {0}
#define RealmID_init_zero                        {0, 0}
#define AccountID_init_zero                      {0, 0, 0}
#define FileID_init_zero                         {0, 0, 0}
#define ContractID_init_zero                     {0, 0, 0}
#define TransactionID_init_zero                  {Timestamp_init_zero, AccountID_init_zero}
#define Key_init_zero                            {0, {ContractID_init_zero}}
#define ThresholdKey_init_zero                   {0, KeyList_init_zero}
#define KeyList_init_zero                        {{{NULL}, NULL}}
#define Signature_init_zero                      {0, {{0, {0}}}}
#define ThresholdSignature_init_zero             {SignatureList_init_zero}
#define SignatureList_init_zero                  {{{NULL}, NULL}}
#define SignaturePair_init_zero                  {{{NULL}, NULL}, 0, {{0, {0}}}}
#define SignatureMap_init_zero                   {{{NULL}, NULL}}
#define FeeComponents_init_zero                  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
#define TransactionFeeSchedule_init_zero         {(LibonomyFunctionality)0, FeeData_init_zero}
#define FeeData_init_zero                        {FeeComponents_init_zero, FeeComponents_init_zero, FeeComponents_init_zero}
#define FeeSchedule_init_zero                    {{{NULL}, NULL}, TimestampSeconds_init_zero}
#define CurrentAndNextFeeSchedule_init_zero      {FeeSchedule_init_zero, FeeSchedule_init_zero}
#define NodeAddress_init_zero                    {{{NULL}, NULL}, 0, {{NULL}, NULL}}
#define NodeAddressBook_init_zero                {{{NULL}, NULL}}
#define Duration_init_zero                       {0}
#define Timestamp_init_zero                      {0, 0}
#define TimestampSeconds_init_zero               {0}
#define CryptoCreateTransactionBody_init_zero    {Key_init_zero, 0, AccountID_init_zero, 0, 0, 0, Duration_init_zero, ShardID_init_zero, RealmID_init_zero, Key_init_zero}
#define CryptoUpdateTransactionBody_init_zero    {AccountID_init_zero, Key_init_zero, AccountID_init_zero, 0, 0, {0}, 0, {0}, Duration_init_zero, Timestamp_init_zero, 0, {0}}
#define AccountAmount_init_zero                  {AccountID_init_zero, 0}
#define TransferList_init_zero                   {0, {AccountAmount_init_zero, AccountAmount_init_zero}}
#define CryptoTransferTransactionBody_init_zero  {TransferList_init_zero}
#define TransactionBody_init_zero                {TransactionID_init_zero, AccountID_init_zero, 0, Duration_init_zero, 0, "", 0, {CryptoCreateTransactionBody_init_zero}}
#define Transaction_init_zero                    {0, {TransactionBody_init_zero}, SignatureList_init_zero, SignatureMap_init_zero}

/* Field tags (for use in manual encoding/decoding) */
#define KeyList_keys_tag                         1
#define NodeAddressBook_nodeAddress_tag          1
#define SignatureList_sigs_tag                   2
#define SignatureMap_sigPair_tag                 1
#define AccountID_shardNum_tag                   1
#define AccountID_realmNum_tag                   2
#define AccountID_accountNum_tag                 3
#define ContractID_shardNum_tag                  1
#define ContractID_realmNum_tag                  2
#define ContractID_contractNum_tag               3
#define Duration_seconds_tag                     1
#define FeeComponents_min_tag                    1
#define FeeComponents_max_tag                    2
#define FeeComponents_constant_tag               3
#define FeeComponents_bpt_tag                    4
#define FeeComponents_vpt_tag                    5
#define FeeComponents_rbs_tag                    6
#define FeeComponents_sbs_tag                    7
#define FeeComponents_gas_tag                    8
#define FeeComponents_tv_tag                     9
#define FeeComponents_bpr_tag                    10
#define FeeComponents_sbpr_tag                   11
#define FileID_shardNum_tag                      1
#define FileID_realmNum_tag                      2
#define FileID_fileNum_tag                       3
#define NodeAddress_ipAddress_tag                1
#define NodeAddress_portno_tag                   2
#define NodeAddress_memo_tag                     3
#define RealmID_shardNum_tag                     1
#define RealmID_realmNum_tag                     2
#define ShardID_shardNum_tag                     1
#define SignaturePair_contract_tag               2
#define SignaturePair_ed25519_tag                3
#define SignaturePair_RSA_3072_tag               4
#define SignaturePair_ECDSA_384_tag              5
#define SignaturePair_pubKeyPrefix_tag           1
#define ThresholdKey_threshold_tag               1
#define ThresholdKey_keys_tag                    2
#define ThresholdSignature_sigs_tag              2
#define Timestamp_seconds_tag                    1
#define Timestamp_nanos_tag                      2
#define TimestampSeconds_seconds_tag             1
#define AccountAmount_accountID_tag              1
#define AccountAmount_amount_tag                 2
#define FeeData_nodedata_tag                     1
#define FeeData_networkdata_tag                  2
#define FeeData_servicedata_tag                  3
#define FeeSchedule_transactionFeeSchedule_tag   1
#define FeeSchedule_expiryTime_tag               2
#define Key_contractID_tag                       1
#define Key_ed25519_tag                          2
#define Key_RSA_3072_tag                         3
#define Key_ECDSA_384_tag                        4
#define Key_thresholdKey_tag                     5
#define Key_keyList_tag                          6
#define Signature_contract_tag                   1
#define Signature_ed25519_tag                    2
#define Signature_RSA_3072_tag                   3
#define Signature_ECDSA_384_tag                  4
#define Signature_thresholdSignature_tag         5
#define Signature_signatureList_tag              6
#define TransactionID_transactionValidStart_tag  1
#define TransactionID_accountID_tag              2
#define CryptoCreateTransactionBody_key_tag      1
#define CryptoCreateTransactionBody_initialBalance_tag 2
#define CryptoCreateTransactionBody_proxyAccountID_tag 3
#define CryptoCreateTransactionBody_sendRecordThreshold_tag 6
#define CryptoCreateTransactionBody_receiveRecordThreshold_tag 7
#define CryptoCreateTransactionBody_receiverSigRequired_tag 8
#define CryptoCreateTransactionBody_autoRenewPeriod_tag 9
#define CryptoCreateTransactionBody_shardID_tag  10
#define CryptoCreateTransactionBody_realmID_tag  11
#define CryptoCreateTransactionBody_newRealmAdminKey_tag 12
#define CryptoUpdateTransactionBody_sendRecordThreshold_tag 6
#define CryptoUpdateTransactionBody_sendRecordThresholdWrapper_tag 11
#define CryptoUpdateTransactionBody_receiveRecordThreshold_tag 7
#define CryptoUpdateTransactionBody_receiveRecordThresholdWrapper_tag 12
#define CryptoUpdateTransactionBody_receiverSigRequired_tag 10
#define CryptoUpdateTransactionBody_receiverSigRequiredWrapper_tag 13
#define CryptoUpdateTransactionBody_accountIDToUpdate_tag 2
#define CryptoUpdateTransactionBody_key_tag      3
#define CryptoUpdateTransactionBody_proxyAccountID_tag 4
#define CryptoUpdateTransactionBody_proxyFraction_tag 5
#define CryptoUpdateTransactionBody_autoRenewPeriod_tag 8
#define CryptoUpdateTransactionBody_expirationTime_tag 9
#define CurrentAndNextFeeSchedule_currentFeeSchedule_tag 1
#define CurrentAndNextFeeSchedule_nextFeeSchedule_tag 2
#define TransactionFeeSchedule_libonomyFunctionality_tag 1
#define TransactionFeeSchedule_feeData_tag       2
#define TransferList_accountAmounts_tag          1
#define CryptoTransferTransactionBody_transfers_tag 1
#define TransactionBody_cryptoCreateAccount_tag  11
#define TransactionBody_cryptoTransfer_tag       14
#define TransactionBody_cryptoUpdateAccount_tag  15
#define TransactionBody_transactionID_tag        1
#define TransactionBody_nodeAccountID_tag        2
#define TransactionBody_transactionFee_tag       3
#define TransactionBody_transactionValidDuration_tag 4
#define TransactionBody_generateRecord_tag       5
#define TransactionBody_memo_tag                 6
#define Transaction_body_tag                     1
#define Transaction_bodyBytes_tag                4
#define Transaction_sigs_tag                     2
#define Transaction_sigMap_tag                   3

/* Struct field encoding specification for nanopb */
extern const pb_field_t ShardID_fields[2];
extern const pb_field_t RealmID_fields[3];
extern const pb_field_t AccountID_fields[4];
extern const pb_field_t FileID_fields[4];
extern const pb_field_t ContractID_fields[4];
extern const pb_field_t TransactionID_fields[3];
extern const pb_field_t Key_fields[7];
extern const pb_field_t ThresholdKey_fields[3];
extern const pb_field_t KeyList_fields[2];
extern const pb_field_t Signature_fields[7];
extern const pb_field_t ThresholdSignature_fields[2];
extern const pb_field_t SignatureList_fields[2];
extern const pb_field_t SignaturePair_fields[6];
extern const pb_field_t SignatureMap_fields[2];
extern const pb_field_t FeeComponents_fields[12];
extern const pb_field_t TransactionFeeSchedule_fields[3];
extern const pb_field_t FeeData_fields[4];
extern const pb_field_t FeeSchedule_fields[3];
extern const pb_field_t CurrentAndNextFeeSchedule_fields[3];
extern const pb_field_t NodeAddress_fields[4];
extern const pb_field_t NodeAddressBook_fields[2];
extern const pb_field_t Duration_fields[2];
extern const pb_field_t Timestamp_fields[3];
extern const pb_field_t TimestampSeconds_fields[2];
extern const pb_field_t CryptoCreateTransactionBody_fields[11];
extern const pb_field_t CryptoUpdateTransactionBody_fields[13];
extern const pb_field_t AccountAmount_fields[3];
extern const pb_field_t TransferList_fields[2];
extern const pb_field_t CryptoTransferTransactionBody_fields[2];
extern const pb_field_t TransactionBody_fields[10];
extern const pb_field_t Transaction_fields[5];

/* Maximum encoded size of messages (where known) */
#define ShardID_size                             11
#define RealmID_size                             22
#define AccountID_size                           33
#define FileID_size                              33
#define ContractID_size                          33
#define TransactionID_size                       59
/* Key_size depends on runtime parameters */
#define ThresholdKey_size                        (12 + KeyList_size)
/* KeyList_size depends on runtime parameters */
/* Signature_size depends on runtime parameters */
#define ThresholdSignature_size                  (6 + SignatureList_size)
/* SignatureList_size depends on runtime parameters */
/* SignaturePair_size depends on runtime parameters */
/* SignatureMap_size depends on runtime parameters */
#define FeeComponents_size                       121
#define TransactionFeeSchedule_size              374
#define FeeData_size                             369
/* FeeSchedule_size depends on runtime parameters */
#define CurrentAndNextFeeSchedule_size           (12 + FeeSchedule_size + FeeSchedule_size)
/* NodeAddress_size depends on runtime parameters */
/* NodeAddressBook_size depends on runtime parameters */
#define Duration_size                            11
#define Timestamp_size                           22
#define TimestampSeconds_size                    11
#define CryptoCreateTransactionBody_size         (132 + Key_size + Key_size)
#define CryptoUpdateTransactionBody_size         (154 + Key_size)
#define AccountAmount_size                       46
#define TransferList_size                        96
#define CryptoTransferTransactionBody_size       98
/* TransactionBody_size depends on runtime parameters */
/* Transaction_size depends on runtime parameters */

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define CREATEACCOUNT_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif
