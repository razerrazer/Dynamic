// Copyright (c) 2017-2018 Duality Blockchain Solutions Developers
// Copyright (c) 2015-2018 The Syscoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alias.h"

#include "assetallocation.h"
#include "base58.h"
#include "chainparams.h"
#include "coincontrol.h"
#include "core_io.h"
#include "init.h"
#include "policy/policy.h"
#include "random.h"
#include "rpcserver.h"
#include "txmempool.h"
#include "validation.h"
#include "wallet/wallet.h"

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <boost/algorithm/string/find.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <boost/xpressive/xpressive_dynamic.hpp>

typedef map<vector<unsigned char>, COutPoint > mapAliasRegistrationsType;
typedef map<vector<unsigned char>, vector<unsigned char> > mapAliasRegistrationsDataType;
mapAliasRegistrationsType mapAliasRegistrations;
mapAliasRegistrationsDataType mapAliasRegistrationData;

extern void SendMoneySyscoin(const vector<unsigned char> &vchAlias, const vector<unsigned char> &vchWitness, const CRecipient &aliasRecipient, CRecipient &aliasPaymentRecipient, vector<CRecipient> &vecSend, CWalletTx& wtxNew, CCoinControl* coinControl, bool fUseInstantSend=false, bool transferAlias=false);

UniValue aliasnew(const UniValue& params, bool fHelp) {
    if (fHelp || 8 != params.size())
        throw runtime_error(
            "aliasnew [aliasname] [public value] [accept_transfers_flags=3] [expire_timestamp] [address] [encryption_privatekey] [encryption_publickey] [witness]\n"
                        "<aliasname> alias name.\n"
                        "<public value> alias public profile data, 256 characters max.\n"
                        "<accept_transfers_flags> 0 for none, 1 for accepting certificate transfers, 2 for accepting asset transfers and 3 for all. Default is 3.\n"    
                        "<expire_timestamp> Epoch time when to expire alias. It is exponentially more expensive per year, calculation is FEERATE*(2.88^years). FEERATE is the dynamic satoshi per byte fee set in the rate peg alias used for this alias. Defaults to 1 hour.\n"    
                        "<address> Address for this alias.\n"       
                        "<encryption_privatekey> Encrypted private key used for encryption/decryption of private data related to this alias. Should be encrypted to publickey.\n"
                        "<encryption_publickey> Public key used for encryption/decryption of private data related to this alias.\n"                     
                        "<witness> Witness alias name that will sign for web-of-trust notarization of this transaction.\n"                          
                        + HelpRequiringPassphrase());
    vector<unsigned char> vchAlias = vchFromString(params[0].get_str());
    string strName = stringFromVch(vchAlias);
    /*Above pattern makes sure domain name matches the following criteria :

    The domain name should be a-z | 0-9 and hyphen(-)
    The domain name should between 3 and 63 characters long
    Last Tld can be 2 to a maximum of 6 characters
    The domain name should not start or end with hyphen (-) (e.g. -syscoin.org or syscoin-.org)
    The domain name can be a subdomain (e.g. sys.blogspot.com)*/

    using namespace boost::xpressive;
    using namespace boost::algorithm;
    to_lower(strName);
    smatch nameparts;
    sregex domainwithtldregex = sregex::compile("^((?!-)[a-z0-9-]{3,64}(?<!-)\\.)+[a-z]{2,6}$");
    sregex domainwithouttldregex = sregex::compile("^((?!-)[a-z0-9-]{3,64}(?<!-))");

    if(find_first(strName, "."))
    {
        if (!regex_search(strName, nameparts, domainwithtldregex) || string(nameparts[0]) != strName)
            throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5505 - " + _("Invalid Syscoin Identity. Must follow the domain name spec of 3 to 64 characters with no preceding or trailing dashes and a TLD of 2 to 6 characters"));   
    }
    else
    {
        if (!regex_search(strName, nameparts, domainwithouttldregex)  || string(nameparts[0]) != strName)
            throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5506 - " + _("Invalid Syscoin Identity. Must follow the domain name spec of 3 to 64 characters with no preceding or trailing dashes"));
    }
    


    vchAlias = vchFromString(strName);

    vector<unsigned char> vchPublicValue;
    string strPublicValue = "";
    strPublicValue = params[1].get_str();
    vchPublicValue = vchFromString(strPublicValue);

    unsigned char nAcceptTransferFlags = 3;
    nAcceptTransferFlags = params[2].get_int();
    uint64_t nTime = 0;
    nTime = params[3].get_int64();
    // sanity check set to 1 hr
    if((int64_t)nTime < chainActive.Tip()->GetMedianTimePast() +3600)
        nTime = chainActive.Tip()->GetMedianTimePast() +3600;

    string strAddress = "";
    strAddress = params[4].get_str();
    
    string strEncryptionPrivateKey = "";
    strEncryptionPrivateKey = params[5].get_str();
    string strEncryptionPublicKey = "";
    strEncryptionPublicKey = params[6].get_str();
    vector<unsigned char> vchWitness;
    vchWitness = vchFromValue(params[7]);

    CWalletTx wtx;

    CAliasIndex oldAlias;
    if(GetAlias(vchAlias, oldAlias))
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5508 - " + _("This alias already exists"));


    const vector<unsigned char> &vchRandAlias = vchFromString(GenerateSyscoinGuid());

    // build alias
    CAliasIndex newAlias;
    newAlias.vchGUID = vchRandAlias;
    newAlias.vchAlias = vchAlias;
    if(!strEncryptionPublicKey.empty())
        newAlias.vchEncryptionPublicKey = ParseHex(strEncryptionPublicKey);
    if(!strEncryptionPrivateKey.empty())
        newAlias.vchEncryptionPrivateKey = ParseHex(strEncryptionPrivateKey);
    newAlias.vchPublicValue = vchPublicValue;
    newAlias.nExpireTime = nTime;
    newAlias.nAcceptTransferFlags = nAcceptTransferFlags;
    if(strAddress.empty())
    {
        // generate new address in this wallet if not passed in
        CKey privKey;
        privKey.MakeNewKey(true);
        CPubKey pubKey = privKey.GetPubKey();
        vector<unsigned char> vchPubKey(pubKey.begin(), pubKey.end());
        CDynamicAddress addressAlias(pubKey.GetID());
        strAddress = addressAlias.ToString();
        if (pwalletMain && !pwalletMain->AddKeyPubKey(privKey, pubKey))
            throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5508 - " + _("Error adding key to wallet"));
    }
    DecodeBase58(strAddress, newAlias.vchAddress);
    CScript scriptPubKeyOrig;
    

    vector<unsigned char> data;
    vector<unsigned char> vchHashAlias;
    uint256 hash;
    bool bActivation = false;

    if(mapAliasRegistrationData.count(vchAlias) > 0)
    {
        data = mapAliasRegistrationData[vchAlias];
        hash = Hash(data.begin(), data.end());
        vchHashAlias = vchFromValue(hash.GetHex());
        if(!newAlias.UnserializeFromData(data, vchHashAlias))
            throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5508 - " + _("Cannot unserialize alias registration transaction"));
        bActivation = true;
    }
    else
    {
        newAlias.Serialize(data);
        hash = Hash(data.begin(), data.end());
        vchHashAlias = vchFromValue(hash.GetHex());
        mapAliasRegistrationData.insert(make_pair(vchAlias, data));
    }


    CScript scriptPubKey;
    if(bActivation)
        scriptPubKey << CScript::EncodeOP_N(OP_DYNAMIC_ALIAS) << CScript::EncodeOP_N(OP_ALIAS_ACTIVATE) << vchAlias << newAlias.vchGUID << vchHashAlias << vchWitness << OP_2DROP << OP_2DROP << OP_2DROP;
    else
        scriptPubKey << CScript::EncodeOP_N(OP_DYNAMIC_ALIAS) << CScript::EncodeOP_N(OP_ALIAS_ACTIVATE) << vchHashAlias << OP_2DROP << OP_DROP;

    CDynamicAddress newAddress;
    GetAddress(newAlias, &newAddress, scriptPubKeyOrig);
    scriptPubKey += scriptPubKeyOrig;

    vector<CRecipient> vecSend;
    CRecipient recipient;
    CreateRecipient(scriptPubKey, recipient);
    CRecipient recipientPayment;
    CreateAliasRecipient(scriptPubKeyOrig, recipientPayment);
    CScript scriptData;
    
    scriptData << OP_RETURN << data;
    CRecipient fee;
    CreateFeeRecipient(scriptData, data, fee);
    // calculate a fee if renewal is larger than default.. based on how many years you extend for it will be exponentially more expensive
    uint64_t nTimeExpiry = nTime - chainActive.Tip()->GetMedianTimePast();
    if (nTimeExpiry < 3600)
        nTimeExpiry = 3600;
    float fYears = nTimeExpiry / ONE_YEAR_IN_SECONDS;
    if(fYears < 1)
        fYears = 1;
    fee.nAmount = GetDataFee(scriptData) * powf(2.88,fYears);
    CCoinControl coinControl;
    if(bActivation && mapAliasRegistrations.count(vchHashAlias) > 0)
    {
        if (pwalletMain)
            pwalletMain->UnlockCoin(mapAliasRegistrations[vchHashAlias]);
        vecSend.push_back(fee);
        // add the registration input to the alias activation transaction
        coinControl.Select(mapAliasRegistrations[vchHashAlias]);
    }
    coinControl.fAllowOtherInputs = true;
    coinControl.fAllowWatchOnly = true;

    SendMoneySyscoin(vchAlias, vchWitness, recipient, recipientPayment, vecSend, wtx, &coinControl);
    UniValue res(UniValue::VARR);
    res.push_back(EncodeHexTx(wtx));
    res.push_back(strAddress);
    return res;
}

UniValue aliaspay(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "aliaspay aliasfrom {\"address\":amount,...} (instantsend subtractfeefromamount)\n"
            "\nSend multiple times from an alias. Amounts are double-precision floating point numbers."
            + HelpRequiringPassphrase() + "\n"
            "\nArguments:\n"
            "1. \"aliasfrom\"           (string, required) Alias to pay from\n"
            "2. \"amounts\"             (string, required) A json object with aliases and amounts\n"
            "    {\n"
            "      \"address\":amount   (numeric or string) The syscoin alias is the key, the numeric amount (can be string) in SYS is the value\n"
            "      ,...\n"
            "    }\n"
            "3. instantsend             (boolean, optional) Set to true to use InstantSend to send this transaction or false otherwise.\n"
            "4. subtractfeefromamount   (string, optional) A json array with addresses.\n"
            "\nResult:\n"
            "\"transaction hex\"          (string) The transaction hex (unsigned) for signing and sending. Only 1 transaction is created regardless of \n"
            "                                    the number of addresses.\n"
            "\nExamples:\n"
            "\nSend two amounts to two different address or aliases, sends 0.01/0.02 SYS representing USD:\n"
            + HelpExampleCli("aliaspay", "\"myalias\" \"USD\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"alias2\\\":0.02}\"") +
            "\nSend two amounts to two different address or aliases while also adding a comment, sends 0.01/0.02 SYS representing USD:\n"
            + HelpExampleCli("aliaspay", "\"myalias\" \"USD\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" \"testing\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    string strFrom = params[0].get_str();
    CAliasIndex theAlias;
    if (!GetAlias(vchFromString(strFrom), theAlias))
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5509 - " + _("Invalid fromalias"));

    UniValue sendTo = params[1].get_obj();

    bool fUseInstantSend = false;
    if (params.size() > 2)
        fUseInstantSend = params[2].get_bool();

    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (params.size() > 3)
        subtractFeeFromAmount = params[3].get_array();


    CWalletTx wtx;
    set<CDynamicAddress> setAddress;
    vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    vector<string> keys = sendTo.getKeys();
    BOOST_FOREACH(const string& name_, keys)
    {
        CDynamicAddress address(name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Syscoin address: ")+name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+name_);
        setAddress.insert(address);
        CScript scriptPubKey = GetScriptForDestination(address.Get());
        CAmount nAmount = AmountFromValue(sendTo[name_]);
        if (nAmount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount;
        bool fSubtractFeeFromAmount = false;
        for (unsigned int idx = 0; idx < subtractFeeFromAmount.size(); idx++) {
            const UniValue& addr = subtractFeeFromAmount[idx];
            if (addr.get_str() == name_)
                fSubtractFeeFromAmount = true;
        }
        CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount };
        vecSend.push_back(recipient);
    }

    EnsureWalletIsUnlocked();
    // Check funds
    UniValue balanceParams(UniValue::VARR);
    balanceParams.push_back(strFrom);
    const UniValue &resBalance = tableRPC.execute("aliasbalance", balanceParams);
    CAmount nBalance = AmountFromValue(find_value(resBalance.get_obj(), "balance"));
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Alias has insufficient funds");

    CRecipient recipient, recipientPayment;
    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = false;
    coinControl.fAllowWatchOnly = false;
    CScript scriptPubKeyOrig;
    CDynamicAddress addressAlias;
    GetAddress(theAlias, &addressAlias, scriptPubKeyOrig);
    CreateAliasRecipient(scriptPubKeyOrig, recipientPayment);   
    SendMoneySyscoin(theAlias.vchAlias, vchFromString(""), recipient, recipientPayment, vecSend, wtx, &coinControl, fUseInstantSend);
    
    UniValue res(UniValue::VARR);
    res.push_back(EncodeHexTx(wtx));
    return res;
}

UniValue aliasupdatewhitelist(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "aliasupdatewhitelist [owner alias] [{\"alias\":\"aliasname\",\"discount_percentage\":n},...] [witness]\n"
            "Update to the whitelist(controls who can resell). Array of whitelist entries in parameter 1.\n"
            "To add to list, include a new alias/discount percentage that does not exist in the whitelist.\n"
            "To update entry, change the discount percentage of an existing whitelist entry.\n"
            "To remove whitelist entry, pass the whilelist entry without changing discount percentage.\n"
            "<owner alias> owner alias controlling this whitelist.\n"
            "   \"entries\"       (string) A json array of whitelist entries to add/remove/update\n"
            "    [\n"
            "      \"alias\"     (string) Alias that you want to add to the affiliate whitelist. Can be '*' to represent that the offers owned by owner alias can be resold by anybody.\n"
            "      \"discount_percentage\"     (number) A discount percentage associated with this alias. The reseller can sell your offer at this discount, not accounting for any commissions he/she may set in his own reselling offer. 0 to 99.\n"
            "      ,...\n"
            "    ]\n"
            "<witness> Witness alias name that will sign for web-of-trust notarization of this transaction.\n"
            + HelpRequiringPassphrase());

    // gather & validate inputs
    vector<unsigned char> vchOwnerAlias = vchFromValue(params[0]);
    UniValue whitelistEntries = params[1].get_array();
    vector<unsigned char> vchWitness;
    vchWitness = vchFromValue(params[2]);
    CWalletTx wtx;

    // this is a syscoin txn
    CScript scriptPubKeyOrig;


    CAliasIndex theAlias;
    if (!GetAlias(vchOwnerAlias, theAlias))
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR ERRCODE: 1518 - " + _("Could not find an alias with this guid"));

    CDynamicAddress aliasAddress;
    GetAddress(theAlias, &aliasAddress, scriptPubKeyOrig);
    CAliasIndex copyAlias = theAlias;
    theAlias.ClearAlias();

    for (unsigned int idx = 0; idx < whitelistEntries.size(); idx++) {
        const UniValue& p = whitelistEntries[idx];
        if (!p.isObject())
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"alias\",\"discount_percentage\"}");

        UniValue whiteListEntryObj = p.get_obj();
        RPCTypeCheckObj(whiteListEntryObj, boost::assign::map_list_of("alias", UniValue::VSTR)("discount_percentage", UniValue::VNUM));
        string aliasEntryName = find_value(whiteListEntryObj, "alias").get_str();
        int nDiscount = find_value(whiteListEntryObj, "discount_percentage").get_int();

        COfferLinkWhitelistEntry entry;
        entry.aliasLinkVchRand = vchFromString(aliasEntryName);
        entry.nDiscountPct = nDiscount;
        theAlias.offerWhitelist.PutWhitelistEntry(entry);

        if (!theAlias.offerWhitelist.GetLinkEntryByHash(vchFromString(aliasEntryName), entry))
            throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR ERRCODE: 1523 - " + _("This alias entry was not added to affiliate list: ") + aliasEntryName);
    }
    vector<unsigned char> data;
    theAlias.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
    vector<unsigned char> vchHashAlias = vchFromValue(hash.GetHex());

    CScript scriptPubKey;
    scriptPubKey << CScript::EncodeOP_N(OP_DYNAMIC_ALIAS) << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << copyAlias.vchAlias << copyAlias.vchGUID << vchHashAlias << vchWitness << OP_2DROP << OP_2DROP << OP_2DROP;
    scriptPubKey += scriptPubKeyOrig;

    vector<CRecipient> vecSend;
    CRecipient recipient;
    CreateRecipient(scriptPubKey, recipient);
    CRecipient recipientPayment;
    CreateAliasRecipient(scriptPubKeyOrig, recipientPayment);
    CScript scriptData;
    scriptData << OP_RETURN << data;
    CRecipient fee;
    CreateFeeRecipient(scriptData, data, fee);
    vecSend.push_back(fee);


    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = false;
    coinControl.fAllowWatchOnly = false;
    SendMoneySyscoin(copyAlias.vchAlias, vchWitness, recipient, recipientPayment, vecSend, wtx, &coinControl);

    UniValue res(UniValue::VARR);
    res.push_back(EncodeHexTx(wtx));
    return res;
}

UniValue aliasclearwhitelist(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "aliasclearwhitelist [owner alias] [witness]\n"
            "Clear your whitelist(controls who can resell).\n"
            + HelpRequiringPassphrase());
    // gather & validate inputs
    vector<unsigned char> vchAlias = vchFromValue(params[0]);
    vector<unsigned char> vchWitness;
    vchWitness = vchFromValue(params[1]);
    // this is a syscoind txn
    CWalletTx wtx;
    CScript scriptPubKeyOrig;


    CAliasIndex theAlias;
    if (!GetAlias(vchAlias, theAlias))
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR ERRCODE: 1529 - " + _("Could not find an alias with this name"));


    CDynamicAddress aliasAddress;
    GetAddress(theAlias, &aliasAddress, scriptPubKeyOrig);

    COfferLinkWhitelistEntry entry;
    // special case to clear all entries for this offer
    entry.nDiscountPct = 127;
    CAliasIndex copyAlias = theAlias;
    theAlias.ClearAlias();
    theAlias.offerWhitelist.PutWhitelistEntry(entry);
    vector<unsigned char> data;
    theAlias.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
    vector<unsigned char> vchHashAlias = vchFromValue(hash.GetHex());

    CScript scriptPubKey;
    scriptPubKey << CScript::EncodeOP_N(OP_DYNAMIC_ALIAS) << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << copyAlias.vchAlias << copyAlias.vchGUID << vchHashAlias << vchWitness << OP_2DROP << OP_2DROP << OP_2DROP;
    scriptPubKey += scriptPubKeyOrig;

    vector<CRecipient> vecSend;
    CRecipient recipient;
    CreateRecipient(scriptPubKey, recipient);
    CRecipient recipientPayment;
    CreateAliasRecipient(scriptPubKeyOrig, recipientPayment);
    CScript scriptData;
    scriptData << OP_RETURN << data;
    CRecipient fee;
    CreateFeeRecipient(scriptData, data, fee);
    vecSend.push_back(fee);


    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = false;
    coinControl.fAllowWatchOnly = false;
    SendMoneySyscoin(copyAlias.vchAlias, vchWitness, recipient, recipientPayment, vecSend, wtx, &coinControl);

    UniValue res(UniValue::VARR);
    res.push_back(EncodeHexTx(wtx));
    return res;
}

UniValue aliasupdate(const UniValue& params, bool fHelp) {
    if (fHelp || 8 != params.size())
        throw runtime_error(
            "aliasupdate [aliasname] [public value] [address] [accept_transfers_flags=3] [expire_timestamp] [encryption_privatekey] [encryption_publickey] [witness]\n"
                        "Update and possibly transfer an alias.\n"
                        "<aliasname> alias name.\n"
                        "<public_value> alias public profile data, 256 characters max.\n"           
                        "<address> Address of alias.\n"     
                        "<accept_transfers_flags> 0 for none, 1 for accepting certificate transfers, 2 for accepting asset transfers and 3 for all. Default is 3.\n"
                        "<expire_timestamp> Epoch time when to expire alias. It is exponentially more expensive per year, calculation is 2.88^years. FEERATE is the dynamic satoshi per byte fee set in the rate peg alias used for this alias. Defaults to 1 hour. Set to 0 if not changing expiration.\n"     
                        "<encryption_privatekey> Encrypted private key used for encryption/decryption of private data related to this alias. If transferring, the key should be encrypted to alias_pubkey.\n"
                        "<encryption_publickey> Public key used for encryption/decryption of private data related to this alias. Useful if you are changing pub/priv keypair for encryption on this alias.\n"                       
                        "<witness> Witness alias name that will sign for web-of-trust notarization of this transaction.\n"  
                        + HelpRequiringPassphrase());
    vector<unsigned char> vchAlias = vchFromString(params[0].get_str());
    string strPrivateValue = "";
    string strPublicValue = "";
    strPublicValue = params[1].get_str();
    
    CWalletTx wtx;
    CAliasIndex updateAlias;
    string strAddress = "";
    strAddress = params[2].get_str();
    
    unsigned char nAcceptTransferFlags = params[3].get_int();
    
    uint64_t nTime = chainActive.Tip()->GetMedianTimePast() +ONE_YEAR_IN_SECONDS;
    nTime = params[4].get_int64();

    string strEncryptionPrivateKey = "";
    strEncryptionPrivateKey = params[5].get_str();
    
    string strEncryptionPublicKey = "";
    strEncryptionPublicKey = params[6].get_str();
    
    vector<unsigned char> vchWitness;
    vchWitness = vchFromValue(params[7]);


    CAliasIndex theAlias;
    if (!GetAlias(vchAlias, theAlias))
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5518 - " + _("Could not find an alias with this name"));


    CAliasIndex copyAlias = theAlias;
    theAlias.ClearAlias();
    if(strPublicValue != stringFromVch(copyAlias.vchPublicValue))
        theAlias.vchPublicValue = vchFromString(strPublicValue);
    if(strEncryptionPrivateKey != HexStr(copyAlias.vchEncryptionPrivateKey))
        theAlias.vchEncryptionPrivateKey = ParseHex(strEncryptionPrivateKey);
    if(strEncryptionPublicKey != HexStr(copyAlias.vchEncryptionPublicKey))
        theAlias.vchEncryptionPublicKey = ParseHex(strEncryptionPublicKey);

    if(strAddress != EncodeBase58(copyAlias.vchAddress))
        DecodeBase58(strAddress, theAlias.vchAddress);
    theAlias.nExpireTime = nTime;
    theAlias.nAccessFlags = copyAlias.nAccessFlags;
    theAlias.nAcceptTransferFlags = nAcceptTransferFlags;
    
    CDynamicAddress newAddress;
    CScript scriptPubKeyOrig;
    if(theAlias.vchAddress.empty())
        GetAddress(copyAlias, &newAddress, scriptPubKeyOrig);
    else
        GetAddress(theAlias, &newAddress, scriptPubKeyOrig);

    vector<unsigned char> data;
    theAlias.Serialize(data);
    uint256 hash = Hash(data.begin(), data.end());
    vector<unsigned char> vchHashAlias = vchFromValue(hash.GetHex());

    CScript scriptPubKey;
    scriptPubKey << CScript::EncodeOP_N(OP_DYNAMIC_ALIAS) << CScript::EncodeOP_N(OP_ALIAS_UPDATE) << copyAlias.vchAlias << copyAlias.vchGUID << vchHashAlias << vchWitness << OP_2DROP << OP_2DROP << OP_2DROP;
    scriptPubKey += scriptPubKeyOrig;

    vector<CRecipient> vecSend;
    CRecipient recipient;
    CreateRecipient(scriptPubKey, recipient);
    CRecipient recipientPayment;
    CreateAliasRecipient(scriptPubKeyOrig, recipientPayment);
    CScript scriptData;
    scriptData << OP_RETURN << data;
    CRecipient fee;
    CreateFeeRecipient(scriptData, data, fee);
    if (nTime > 0) {
        // calculate a fee if renewal is larger than default.. based on how many years you extend for it will be exponentially more expensive
        uint64_t nTimeExpiry = nTime - chainActive.Tip()->GetMedianTimePast();
        if (nTimeExpiry < 3600)
            nTimeExpiry = 3600;
        float fYears = nTimeExpiry / ONE_YEAR_IN_SECONDS;
        if (fYears < 1)
            fYears = 1;
        fee.nAmount = GetDataFee(scriptData) * powf(2.88, fYears);
    }
    
    vecSend.push_back(fee);
    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = false;
    coinControl.fAllowWatchOnly = false;
    bool transferAlias = false;
    if(newAddress.ToString() != EncodeBase58(copyAlias.vchAddress))
        transferAlias = true;
    
    SendMoneySyscoin(vchAlias, vchWitness, recipient, recipientPayment, vecSend, wtx, &coinControl, false, transferAlias);
    UniValue res(UniValue::VARR);
    res.push_back(EncodeHexTx(wtx));
    return res;
}

UniValue prunesyscoinservices(const UniValue& params, bool fHelp)
{
    int servicesCleaned = 0;
    CleanupSyscoinServiceDatabases(servicesCleaned);
    UniValue res(UniValue::VOBJ);
    res.push_back(Pair("services_cleaned", servicesCleaned));
    return res;
}

UniValue aliasbalance(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "aliasbalance \"alias\"\n"
            "\nReturns the total amount received by the given alias in transactions.\n"
            "\nArguments:\n"
            "1. \"alias\"  (string, required) The syscoin alias for transactions.\n"
       );
    vector<unsigned char> vchAlias = vchFromValue(params[0]);
    CAmount nAmount = 0;
    CAliasIndex theAlias;
    if (!GetAlias(vchAlias, theAlias))
    {
        UniValue res(UniValue::VOBJ);
        res.push_back(Pair("balance", ValueFromAmount(nAmount)));
        return  res;
    }

    const string &strAddressFrom = EncodeBase58(theAlias.vchAddress);
    UniValue paramsUTXO(UniValue::VARR);
    UniValue param(UniValue::VOBJ);
    UniValue utxoParams(UniValue::VARR);
    utxoParams.push_back(strAddressFrom);
    param.push_back(Pair("addresses", utxoParams));
    paramsUTXO.push_back(param);
    const UniValue &resUTXOs = tableRPC.execute("getaddressutxos", paramsUTXO);
    UniValue utxoArray(UniValue::VARR);
    if (resUTXOs.isArray())
        utxoArray = resUTXOs.get_array();
    else
    {
        UniValue res(UniValue::VOBJ);
        res.push_back(Pair("balance", ValueFromAmount(nAmount)));
        return  res;
    }

    int op;
    vector<vector<unsigned char> > vvch;
    for (unsigned int i = 0;i<utxoArray.size();i++)
    {
        const UniValue& utxoObj = utxoArray[i].get_obj();
        const uint256& txid = uint256S(find_value(utxoObj, "txid").get_str());
        const int& nOut = find_value(utxoObj, "outputIndex").get_int();
        const std::vector<unsigned char> &data(ParseHex(find_value(utxoObj, "script").get_str()));
        const CScript& scriptPubKey = CScript(data.begin(), data.end());
        const CAmount &nValue = AmountFromValue(find_value(utxoObj, "satoshis"));
        if (DecodeAliasScript(scriptPubKey, op, vvch))
            continue;
        // some smaller sized outputs are reserved to pay for fees only using aliasselectpaymentcoins (with bSelectFeePlacement set to true)
        if (nValue <= minRelayTxFee.GetFee(3000))
            continue;
        {
            LOCK(mempool.cs);
            auto it = mempool.mapNextTx.find(COutPoint(txid, nOut));
            if (it != mempool.mapNextTx.end())
                continue;
        }
        nAmount += nValue;
        
    }
    UniValue res(UniValue::VOBJ);
    res.push_back(Pair("balance", ValueFromAmount(nAmount)));
    return  res;
}

UniValue syscoinsendrawtransaction(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error("syscoinsendrawtransaction \"hexstring\" ( allowhighfees instantsend )\n"
            "\nSubmits raw transaction (serialized, hex-encoded) to local node and network.\n"
            "\nAlso see createrawtransaction and signrawtransaction calls.\n"
            "\nArguments:\n"
            "1. \"hexstring\"    (string, required) The hex string of the raw transaction)\n"
            "2. allowhighfees  (boolean, optional, default=false) Allow high fees\n"
            "3. instantsend    (boolean, optional, default=false) Use InstantSend to send this transaction\n");
    RPCTypeCheck(params, boost::assign::list_of(UniValue::VSTR)(UniValue::VBOOL)(UniValue::VBOOL));
    const string &hexstring = params[0].get_str();
    bool fOverrideFees = false;
    if (params.size() > 1)
        fOverrideFees = params[1].get_bool();

    bool fInstantSend = false;
    if (params.size() > 2)
        fInstantSend = params[2].get_bool();
    CTransaction tx;
    if (!DecodeHexTx(tx, hexstring))
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5534 - " + _("Could not send raw transaction: Cannot decode transaction from hex string"));
    if (tx.vin.size() <= 0)
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5534 - " + _("Could not send raw transaction: Inputs are empty"));
    if (tx.vout.size() <= 0)
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5534 - " + _("Could not send raw transaction: Outputs are empty"));
    UniValue arraySendParams(UniValue::VARR);
    arraySendParams.push_back(hexstring);
    arraySendParams.push_back(fOverrideFees);
    arraySendParams.push_back(fInstantSend);
    UniValue returnRes;
    try
    {
        returnRes = tableRPC.execute("sendrawtransaction", arraySendParams);
    }
    catch (UniValue& objError)
    {
        throw runtime_error(find_value(objError, "message").get_str());
    }
    if (!returnRes.isStr())
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5534 - " + _("Could not send raw transaction: Invalid response from sendrawtransaction"));
    UniValue res(UniValue::VOBJ);
    res.push_back(Pair("txid", returnRes.get_str()));
    // check for alias registration, if so save the info in this node for alias activation calls after a block confirmation
    vector<vector<unsigned char> > vvch;
    int op;
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];
        if (DecodeAliasScript(out.scriptPubKey, op, vvch) && op == OP_ALIAS_ACTIVATE) 
        {
            if(vvch.size() == 1)
            {
                if (!mapAliasRegistrations.count(vvch[0])) {
                    COutPoint prevOut(tx.GetHash(), i);
                    mapAliasRegistrations.insert(make_pair(vvch[0], prevOut));
                    if(pwalletMain)
                        pwalletMain->LockCoin(prevOut);
                }
            }
            else if(vvch.size() >= 3)
            {
                if(mapAliasRegistrations.count(vvch[2]) > 0)
                    mapAliasRegistrations.erase(vvch[2]);
                if(mapAliasRegistrationData.count(vvch[0]) > 0)
                    mapAliasRegistrationData.erase(vvch[0]);
            }
            break;
        }
    }
    
    return res;
}
/**
 * [aliasinfo description]
 * @param  params [description]
 * @param  fHelp  [description]
 * @return        [description]
 */
UniValue aliasinfo(const UniValue& params, bool fHelp) {
    if (fHelp || 1 > params.size())
        throw runtime_error("aliasinfo <aliasname>\n"
                "Show values of an alias.\n");
    vector<unsigned char> vchAlias = vchFromValue(params[0]);
    CAliasIndex txPos;
    if (!paliasdb || !paliasdb->ReadAlias(vchAlias, txPos))
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5535 - " + _("Failed to read from alias DB"));

    UniValue oName(UniValue::VOBJ);
    if(!BuildAliasJson(txPos, oName))
        throw runtime_error("DYNAMIC_ALIAS_RPC_ERROR: ERRCODE: 5536 - " + _("Could not find this alias"));
        
    return oName;
}

UniValue aliasaddscript(const UniValue& params, bool fHelp) {
    if (fHelp || 1 != params.size())
        throw runtime_error("aliasaddscript redeemscript\n"
                "Add redeemscript to local wallet for signing smart contract based alias transactions.\n");
    std::vector<unsigned char> data(ParseHex(params[0].get_str()));
    if(pwalletMain)
        pwalletMain->AddCScript(CScript(data.begin(), data.end()));
    UniValue res(UniValue::VOBJ);
    res.push_back(Pair("result", "success"));
    return res;
}

UniValue aliaswhitelist(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error("aliaswhitelist <alias>\n"
            "List all affiliates for this alias.\n");
    UniValue oRes(UniValue::VARR);
    vector<unsigned char> vchAlias = vchFromValue(params[0]);

    CAliasIndex theAlias;

    if (!GetAlias(vchAlias, theAlias))
        throw runtime_error("could not find alias with this guid");

    for (auto const &it : theAlias.offerWhitelist.entries)
    {
        const COfferLinkWhitelistEntry& entry = it.second;
        UniValue oList(UniValue::VOBJ);
        oList.push_back(Pair("alias", stringFromVch(entry.aliasLinkVchRand)));
        oList.push_back(Pair("discount_percentage", entry.nDiscountPct));
        oRes.push_back(oList);
    }
    return oRes;
}

static const CRPCCommand commands[] =
{   // category             name                        actor (function)           okSafeMode
#ifdef ENABLE_WALLET
    /* Alias */
    { "services",           "aliasnew",                 &aliasnew,                 true  },
    { "services",           "aliasupdate",              &aliasupdate,              true  },
    { "services",           "aliasinfo",                &aliasinfo,                true  },
    { "services",           "aliasbalance",             &aliasbalance,             true  },
    { "services",           "prunesyscoinservices",     &prunesyscoinservices,     true  },
    { "services",           "aliaspay",                 &aliaspay,                 true  },
    { "services",           "aliasaddscript",           &aliasaddscript,           true  },
    { "services",           "aliasupdatewhitelist",     &aliasupdatewhitelist,     true  },
    { "services",           "aliasclearwhitelist",      &aliasclearwhitelist,      true  },
    { "services",           "aliaswhitelist",           &aliaswhitelist,           true  },
#endif //ENABLE_WALLET
};

void RegisterAliasRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}