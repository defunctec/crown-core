# Crown Revival — Historical PR #1 Baseline Audit

## Scope and constraints
- Audit-only task.
- No production source changes were made in this audit branch.
- Temporary with/without testing was done in detached/worktree states under `/tmp`.

## 1) PR #1 identity and exact metadata

PR URL: <https://github.com/defunctec/crown-core/pull/1>

- **PR #1 title:** `Enforce Unique IP to MN/SN`
- **PR #1 merge commit SHA:** `487053abf22c7bacdfad80fad1081f856db9b940`
- **Author:** `defunctec <defuncteconomics@gmail.com>`
- **Merge date:** `2024-07-19 22:28:47 +0100` (`2024-07-19T21:28:47Z`)
- **Base commit (PR base):** `2fcf128252b2710a2cd7028d44ff4ca02d519cfe`
- **Head commit (PR head):** `3a5bc490e2f924347edf2e449e18a000b6cc464d`

### Exact files changed by PR #1
1. `src/amount.h`
2. `src/masternode.cpp`
3. `src/masternodeman.cpp`
4. `src/masternodeman.h`
5. `src/qt/createnodedialog.cpp`
6. `src/rpcmasternode.cpp`
7. `src/rpcsystemnode.cpp`
8. `src/systemnode.cpp`
9. `src/systemnodeman.cpp`
10. `src/systemnodeman.h`

### Exact production functions/paths changed
- `src/amount.h`
  - `MAX_MONEY` constant (`21000000 * COIN` -> `42000000 * COIN`)
- `src/masternode.cpp`
  - `CMasternodeBroadcast::CheckAndUpdate(int& nDos) const`
  - `CMasternodeBroadcast::CheckInputsAndAdd(int& nDoS) const`
- `src/masternodeman.h/.cpp`
  - Added `CMasternodeMan::IsAddressInUse(const CService& addr)`
- `src/systemnode.cpp`
  - `CSystemnodeBroadcast::CheckAndUpdate(int& nDos) const`
  - `CSystemnodeBroadcast::CheckInputsAndAdd(int& nDoS) const`
- `src/systemnodeman.h/.cpp`
  - Added declaration/definition `CSystemnodeMan::Find(const CScript& payee)`
  - Added `CSystemnodeMan::IsAddressInUse(const CService& addr)`
  - Minor refactor in `CSystemnodeMan::GetCurrentSystemNode(...)` variable naming/extraction
- `src/qt/createnodedialog.cpp`
  - `CreateNodeDialog::CheckIP()`
- `src/rpcmasternode.cpp`
  - `masternode(...)` command handling (`connect`, `start`, `start-alias`, `start-many/start-all/start-missing/start-disabled` paths)
  - `masternodebroadcast(...)` (`create-alias`, `create-all` paths)
- `src/rpcsystemnode.cpp`
  - `systemnode(...)` command handling (`connect`, `start-alias`, `start-many/start-all/start-missing/start-disabled` paths)
  - `systemnodebroadcast(...)` (`create-alias`, `create-all` paths)

### Complete effective PR #1 diff
(Generated from `git diff 2fcf128252b2710a2cd7028d44ff4ca02d519cfe..3a5bc490e2f924347edf2e449e18a000b6cc464d`)

```diff
diff --git a/src/amount.h b/src/amount.h
index c0d37954c..93c22293b 100644
--- a/src/amount.h
+++ b/src/amount.h
@@ -17,7 +17,7 @@ static const CAmount COIN = 100000000;
 static const CAmount CENT = 1000000;
 
 /** No amount larger than this (in satoshi) is valid */
-static const CAmount MAX_MONEY = 21000000 * COIN;
+static const CAmount MAX_MONEY = 42000000 * COIN;
 inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
 
 /** Type-safe wrapper class to for fee rates
diff --git a/src/masternode.cpp b/src/masternode.cpp
index 8539e8557..67ed2944e 100644
--- a/src/masternode.cpp
+++ b/src/masternode.cpp
@@ -586,32 +586,52 @@ bool CMasternodeBroadcast::CheckAndUpdate(int& nDos) const
         if(addr.GetPort() != 9340) return false;
     } else if(addr.GetPort() == 9340) return false;
 
-    //search existing Masternode list, this is where we update existing Masternodes with new mnb broadcasts
+    // Setting pmn to the masternode found using the given IPv4 address
+    CMasternode* pmn = mnodeman.Find(addr);
+
+    // Check if the IPv4 address is found and the vin obtained from the corresponding IPv4 address
+    // does not match the vin of the masternode attempting to broadcast
+    if (pmn && pmn->vin != vin) {
+        // Check if found Masternode is enabled and online
+        if (pmn->IsEnabled()) {
+        // Check if the signing time of the new broadcast is later than the signing time of the initial broadcast
+        // to enable the found masternode. If the new broadcast is more recent, it could be malicious and should be banned.
+            if (sigTime > pmn->sigTime) {
+                LogPrintf("CMasternodeBroadcast::CheckAndUpdate -- IP address already in use by another enabled masternode %s\n", addr.ToString());
+                // Increment DoS score for duplicate IP
+                nDoS = 33;
+                // Stop the node from broadcasting and ultimately enforcing unique IPv4
+                return false;
+            }
+        }
+    }
+
+    // search existing Masternode list, this is where we update existing Masternodes with new mnb broadcasts
     CMasternode* pmn = mnodeman.Find(vin);
 
     // no such masternode, nothing to update
-    if(pmn == NULL) return true;
+    if (pmn == NULL) return true;
 
-    // this broadcast is older or equal than the one that we already have - it's bad and should never happen
+    // this broadcast is older or equal to the one that we already have - it's bad and should never happen
     // unless someone is doing something fishy
     // (mapSeenMasternodeBroadcast in CMasternodeMan::ProcessMessage should filter legit duplicates)
-    if(pmn->sigTime >= sigTime) {
+    if (pmn->sigTime >= sigTime) {
         LogPrintf("CMasternodeBroadcast::CheckAndUpdate - Bad sigTime %d for Masternode %20s %105s (existing broadcast is at %d)\n",
-                      sigTime, addr.ToString(), vin.ToString(), pmn->sigTime);
+                  sigTime, addr.ToString(), vin.ToString(), pmn->sigTime);
         return false;
     }
 
     // masternode is not enabled yet/already, nothing to update
-    if(!pmn->IsEnabled()) return true;
+    if (!pmn->IsEnabled()) return true;
 
     // mn.pubkey = pubkey, IsVinAssociatedWithPubkey is validated once below,
     //   after that they just need to match
-    if(pmn->pubkey == pubkey && !pmn->IsBroadcastedWithin(MASTERNODE_MIN_MNB_SECONDS)) {
-        //take the newest entry
+    if (pmn->pubkey == pubkey && !pmn->IsBroadcastedWithin(MASTERNODE_MIN_MNB_SECONDS)) {
+        // take the newest entry
         LogPrintf("mnb - Got updated entry for %s\n", addr.ToString());
-        if(pmn->UpdateFromNewBroadcast((*this))){
+        if (pmn->UpdateFromNewBroadcast((*this))) {
             pmn->Check();
-            if(pmn->IsEnabled()) Relay();
+            if (pmn->IsEnabled()) Relay();
         }
         masternodeSync.AddedMasternodeList(GetHash());
     }
@@ -640,23 +660,30 @@ bool CMasternodeBroadcast::CheckInputsAndAdd(int& nDoS) const
         else mnodeman.Remove(pmn->vin);
     }
 
+    // Check if the IP address is already in use
+    if (mnodeman.IsAddressInUse(addr)) {
+        LogPrintf("CMasternodeBroadcast::CheckInputsAndAdd -- IP address already in use %s\n", addr.ToString());
+        nDoS = 33;  // Increment DoS score for duplicate IP
+        return false;
+    }
+
     CValidationState state;
     CMutableTransaction tx = CMutableTransaction();
-    CTxOut vout = CTxOut((MASTERNODE_COLLATERAL - 0.01)*COIN, legacySigner.collateralPubKey);
+    CTxOut vout = CTxOut((MASTERNODE_COLLATERAL - 0.01) * COIN, legacySigner.collateralPubKey);
     tx.vin.push_back(vin);
     tx.vout.push_back(vout);
 
     {
         TRY_LOCK(cs_main, lockMain);
-        if(!lockMain) {
+        if (!lockMain) {
             // not mnb fault, let it to be checked again later
             mnodeman.mapSeenMasternodeBroadcast.erase(GetHash());
             masternodeSync.mapSeenSyncMNB.erase(GetHash());
             return false;
         }
 
-        if(!AcceptableInputs(mempool, state, CTransaction(tx), false, NULL)) {
-            //set nDos
+        if (!AcceptableInputs(mempool, state, CTransaction(tx), false, NULL)) {
+            // set nDos
             state.IsInvalid(nDoS);
             return false;
         }
@@ -664,7 +691,7 @@ bool CMasternodeBroadcast::CheckInputsAndAdd(int& nDoS) const
 
     LogPrint("masternode", "mnb - Accepted Masternode entry\n");
 
-    if(GetInputAge(vin) < MASTERNODE_MIN_CONFIRMATIONS){
+    if (GetInputAge(vin) < MASTERNODE_MIN_CONFIRMATIONS) {
         LogPrintf("mnb - Input must have at least %d confirmations\n", MASTERNODE_MIN_CONFIRMATIONS);
         // maybe we miss few blocks, let this mnb to be checked again later
         mnodeman.mapSeenMasternodeBroadcast.erase(GetHash());
@@ -678,12 +705,10 @@ bool CMasternodeBroadcast::CheckInputsAndAdd(int& nDoS) const
     CTransaction tx2;
     GetTransaction(vin.prevout.hash, tx2, hashBlock, true);
     BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
-    if (mi != mapBlockIndex.end() && (*mi).second)
-    {
+    if (mi != mapBlockIndex.end() && (*mi).second) {
         CBlockIndex* pMNIndex = (*mi).second; // block for 10000 CRW tx -> 1 confirmation
         CBlockIndex* pConfIndex = chainActive[pMNIndex->nHeight + MASTERNODE_MIN_CONFIRMATIONS - 1]; // block where tx got MASTERNODE_MIN_CONFIRMATIONS
-        if(pConfIndex->GetBlockTime() > sigTime)
-        {
+        if (pConfIndex->GetBlockTime() > sigTime) {
             LogPrintf("mnb - Bad sigTime %d for Masternode %20s %105s (%i conf block is at %d)\n",
                       sigTime, addr.ToString(), vin.ToString(), MASTERNODE_MIN_CONFIRMATIONS, pConfIndex->GetBlockTime());
             return false;
@@ -695,7 +720,7 @@ bool CMasternodeBroadcast::CheckInputsAndAdd(int& nDoS) const
     mnodeman.Add(mn);
 
     // if it matches our Masternode privkey, then we've been remotely activated
-    if(pubkey2 == activeMasternode.pubKeyMasternode && protocolVersion == PROTOCOL_VERSION){
+    if (pubkey2 == activeMasternode.pubKeyMasternode && protocolVersion == PROTOCOL_VERSION) {
         activeMasternode.EnableHotColdMasterNode(vin, addr);
         if (!vchSignover.empty()) {
             if (pubkey.Verify(pubkey2.GetHash(), vchSignover)) {
@@ -710,9 +735,9 @@ bool CMasternodeBroadcast::CheckInputsAndAdd(int& nDoS) const
     }
 
     bool isLocal = addr.IsRFC1918() || addr.IsLocal();
-    if(Params().NetworkID() == CBaseChainParams::REGTEST) isLocal = false;
+    if (Params().NetworkID() == CBaseChainParams::REGTEST) isLocal = false;
 
-    if(!isLocal) Relay();
+    if (!isLocal) Relay();
 
     return true;
 }
diff --git a/src/masternodeman.cpp b/src/masternodeman.cpp
index 2cefd8a18..b55ae9b0c 100644
--- a/src/masternodeman.cpp
+++ b/src/masternodeman.cpp
@@ -238,6 +238,17 @@ void CMasternodeMan::DsegUpdate(CNode* pnode)
     mWeAskedForMasternodeList[pnode->addr] = askAgain;
 }
 
+bool CMasternodeMan::IsAddressInUse(const CService& addr)
+{
+    LOCK(cs);
+    for (const auto& mn : vMasternodes) {
+        if (mn.addr == addr) {
+            return true;
+        }
+    }
+    return false;
+}
+
 CMasternode *CMasternodeMan::Find(const CScript &payee)
 {
     LOCK(cs);
diff --git a/src/masternodeman.h b/src/masternodeman.h
index 5c8c6a175..ca9069943 100644
--- a/src/masternodeman.h
+++ b/src/masternodeman.h
@@ -88,6 +88,9 @@ public:
 
     void DsegUpdate(CNode* pnode);
 
+    /// Check if an IP address is already in use by another masternode
+    bool IsAddressInUse(const CService& addr);
+
     /// Find an entry
     CMasternode* Find(const CScript &payee);
     CMasternode* Find(const CTxIn& vin);
diff --git a/src/qt/createnodedialog.cpp b/src/qt/createnodedialog.cpp
index 7b8c6b2eb..72e0fd643 100644
--- a/src/qt/createnodedialog.cpp
+++ b/src/qt/createnodedialog.cpp
@@ -1,7 +1,10 @@
 #include "createnodedialog.h"
 #include "ui_createnodedialog.h"
 #include "ui_interface.h"
+#include "masternodeman.h"
+#include "systemnodeman.h"
 #include "net.h"
+#include "netbase.h"
 #include <QMessageBox>
 #include <QPushButton>
 
@@ -94,30 +97,60 @@ bool CreateNodeDialog::CheckAlias()
 bool CreateNodeDialog::CheckIP()
 {
     QString ip = ui->ipEdit->text();
-    // Check ip
+
+    // Check if IP address field is empty
     if (ip.isEmpty())
     {
         ui->ipEdit->setValid(false);
         QMessageBox::warning(this, windowTitle(), tr("IP is Required"), QMessageBox::Ok, QMessageBox::Ok);
         return false;
     }
-    // Check if port is not entered
+
+    // Check if port is entered along with the IP address
     if (ip.contains(QRegExp(":+[0-9]")))
     {
         ui->ipEdit->setValid(false);
         QMessageBox::warning(this, windowTitle(), tr("Enter IP Without Port"), QMessageBox::Ok, QMessageBox::Ok);
         return false;
     }
-    // Validate ip address
-    // This is only for validation so port doesn't matter
-    if (!(CService(ip.toStdString() + ":9340").IsIPv4() && CService(ip.toStdString()).IsRoutable())) {
+
+    // Validate IP address format
+    // Note: This is only for validation so port doesn't matter for this check
+    CService addr(ip.toStdString(), 9340); // Default port set to 9340
+    if (!(addr.IsIPv4() && addr.IsRoutable())) {
         ui->ipEdit->setValid(false);
         QMessageBox::warning(this, windowTitle(), tr("Invalid IP Address. IPV4 ONLY"), QMessageBox::Ok, QMessageBox::Ok);
         return false;
     }
+
+    // Check if the IP address is already in use by another Masternode or Systemnode
+    try {
+        if (mnodeman.IsAddressInUse(addr)) {
+            ui->ipEdit->setValid(false);
+            QMessageBox::warning(this, windowTitle(), tr("IP address is already in use by another Masternode."), QMessageBox::Ok, QMessageBox::Ok);
+            return false;
+        }
+
+        if (snodeman.IsAddressInUse(addr)) {
+            ui->ipEdit->setValid(false);
+            QMessageBox::warning(this, windowTitle(), tr("IP address is already in use by another Systemnode."), QMessageBox::Ok, QMessageBox::Ok);
+            return false;
+        }
+    } catch (const std::exception &e) {
+        ui->ipEdit->setValid(false);
+        QMessageBox::critical(this, windowTitle(), tr("An error occurred while checking the IP address: %1").arg(e.what()), QMessageBox::Ok, QMessageBox::Ok);
+        return false;
+    } catch (...) {
+        ui->ipEdit->setValid(false);
+        QMessageBox::critical(this, windowTitle(), tr("An unknown error occurred while checking the IP address."), QMessageBox::Ok, QMessageBox::Ok);
+        return false;
+    }
+
+    // IP address is valid and not in use
     return true;
 }
 
+
 void CreateNodeDialog::accept()
 {
     ui->buttonBox->button(QDialogButtonBox::Ok)->setFocus();
diff --git a/src/rpcmasternode.cpp b/src/rpcmasternode.cpp
index e009704b5..cba46896f 100644
--- a/src/rpcmasternode.cpp
+++ b/src/rpcmasternode.cpp
@@ -8,13 +8,19 @@
 #include "main.h"
 #include "db.h"
 #include "init.h"
-#include "activemasternode.h"
+#include "net.h"
+#include "masternodeconfig.h"
+#include "masternode.h"
 #include "masternodeman.h"
 #include "masternode-payments.h"
 #include "masternode-budget.h"
-#include "masternodeconfig.h"
+#include "activemasternode.h"
 #include "rpcserver.h"
 #include "utilmoneystr.h"
+#include "wallet.h"
+#include "key.h"
+#include "base58.h"
+#include "netbase.h"
 
 #include <fstream>
 using namespace json_spirit;
@@ -109,6 +115,7 @@ Value masternode(const Array& params, bool fHelp)
                 "\nAvailable commands:\n"
                 "  count        - Print number of all known masternodes (optional: 'ls', 'enabled', 'all', 'qualify')\n"
                 "  current      - Print info on current masternode winner\n"
+                "  connect      - Test the connection to a Masternode using node collateral address\n"
                 "  debug        - Print masternode status\n"
                 "  enforce      - Enforce masternode payments\n"
                 "  outputs      - Print masternode compatible outputs\n"
@@ -133,23 +140,30 @@ Value masternode(const Array& params, bool fHelp)
         return "Show budgets";
     }
 
-    if(strCommand == "connect")
+    if (strCommand == "connect")
     {
         std::string strAddress = "";
-        if (params.size() == 2){
+        if (params.size() == 2) {
             strAddress = params[1].get_str();
         } else {
             throw runtime_error("Masternode address required\n");
         }
 
-        CService addr = CService(strAddress);
+        CService addr;
+        try {
+            addr = CService(strAddress);
+        } catch (const std::exception &e) {
+            throw runtime_error("Invalid address format: " + std::string(e.what()) + "\n");
+        } catch (...) {
+            throw runtime_error("An unknown error occurred while parsing the address\n");
+        }
 
         CNode *pnode = ConnectNode((CAddress)addr, NULL, false);
-        if(pnode){
+        if (pnode) {
             pnode->Release();
-            return "successfully connected";
+            return "Successfully connected to " + addr.ToString();
         } else {
-            throw runtime_error("error connecting\n");
+            throw runtime_error("Error connecting to " + addr.ToString() + "\n");
         }
     }
 
@@ -217,14 +231,22 @@ Value masternode(const Array& params, bool fHelp)
 
     if (strCommand == "start")
     {
-        if(!fMasterNode) throw runtime_error("you must set masternode=1 in the configuration\n");
+        if (!fMasterNode) throw runtime_error("you must set masternode=1 in the configuration\n");
 
         {
             LOCK(pwalletMain->cs_wallet);
             EnsureWalletIsUnlocked();
         }
 
-        if(activeMasternode.status != ACTIVE_MASTERNODE_STARTED){
+        // Get the IP address of the active masternode
+        CService addr = activeMasternode.service;
+
+        // Check if the IP address is already in use by another masternode
+        if (mnodeman.IsAddressInUse(addr)) {
+            throw runtime_error("IP address is already in use by another masternode");
+        }
+
+        if (activeMasternode.status != ACTIVE_MASTERNODE_STARTED) {
             activeMasternode.status = ACTIVE_MASTERNODE_INITIAL; // TODO: consider better way
             activeMasternode.ManageStatus();
         }
@@ -255,6 +277,15 @@ Value masternode(const Array& params, bool fHelp)
                 found = true;
                 std::string errorMessage;
                 CMasternodeBroadcast mnb;
+                
+                // Check if the IP address is already in use by another masternode
+                CService addr(mne.getIp());
+
+                if (mnodeman.IsAddressInUse(addr)) {
+                    statusObj.push_back(Pair("result", "failed"));
+                    statusObj.push_back(Pair("errorMessage", "IP address is already in use by another masternode."));
+                    break;
+                }
 
                 bool result = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage, mnb);
 
@@ -278,63 +309,76 @@ Value masternode(const Array& params, bool fHelp)
 
     }
 
-    if (strCommand == "start-many" || strCommand == "start-all" || strCommand == "start-missing" || strCommand == "start-disabled")
-    {
+if (strCommand == "start-many" || strCommand == "start-all" || strCommand == "start-missing" || strCommand == "start-disabled")
+{
 
-        {
-            LOCK(pwalletMain->cs_wallet);
-            EnsureWalletIsUnlocked();
-        }
+    {
+        LOCK(pwalletMain->cs_wallet);
+        EnsureWalletIsUnlocked();
+    }
 
-        if((strCommand == "start-missing" || strCommand == "start-disabled") &&
+    if ((strCommand == "start-missing" || strCommand == "start-disabled") &&
          (masternodeSync.RequestedMasternodeAssets <= MASTERNODE_SYNC_LIST ||
           masternodeSync.RequestedMasternodeAssets == MASTERNODE_SYNC_FAILED)) {
-            throw runtime_error("You can't use this command until masternode list is synced\n");
-        }
-
-        std::vector<CNodeEntry> mnEntries;
-        mnEntries = masternodeConfig.getEntries();
+        throw runtime_error("You can't use this command until masternode list is synced\n");
+    }
 
-        int successful = 0;
-        int failed = 0;
+    std::vector<CNodeEntry> mnEntries;
+    mnEntries = masternodeConfig.getEntries();
 
-        Object resultsObj;
+    int successful = 0;
+    int failed = 0;
 
-        BOOST_FOREACH(CNodeEntry mne, masternodeConfig.getEntries()) {
-            std::string errorMessage;
+    Object resultsObj;
 
-            CTxIn vin = CTxIn(uint256S(mne.getTxHash()), uint32_t(atoi(mne.getOutputIndex().c_str())));
-            CMasternode *pmn = mnodeman.Find(vin);
-            CMasternodeBroadcast mnb;
+    BOOST_FOREACH(CNodeEntry mne, masternodeConfig.getEntries()) {
+        std::string errorMessage;
 
-            if(strCommand == "start-missing" && pmn) continue;
-            if(strCommand == "start-disabled" && pmn && pmn->IsEnabled()) continue;
+        CTxIn vin = CTxIn(uint256S(mne.getTxHash()), uint32_t(atoi(mne.getOutputIndex().c_str())));
+        CMasternode *pmn = mnodeman.Find(vin);
+        CMasternodeBroadcast mnb;
 
-            bool result = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage, mnb);
+        if (strCommand == "start-missing" && pmn) continue;
+        if (strCommand == "start-disabled" && pmn && pmn->IsEnabled()) continue;
 
+        // Check if the IP address is already in use by another masternode
+        CService addr(mne.getIp());
+        if (mnodeman.IsAddressInUse(addr)) {
+            failed++;
             Object statusObj;
             statusObj.push_back(Pair("alias", mne.getAlias()));
-            statusObj.push_back(Pair("result", result ? "successful" : "failed"));
-
-            if(result) {
-                successful++;
-                mnodeman.UpdateMasternodeList(mnb);
-                mnb.Relay();
-            } else {
-                failed++;
-                statusObj.push_back(Pair("errorMessage", errorMessage));
-            }
-
+            statusObj.push_back(Pair("result", "failed"));
+            statusObj.push_back(Pair("errorMessage", "IP address is already in use by another masternode."));
             resultsObj.push_back(Pair("status", statusObj));
+            continue; // Skip to the next entry
         }
 
-        Object returnObj;
-        returnObj.push_back(Pair("overall", strprintf("Successfully started %d masternodes, failed to start %d, total %d", successful, failed, successful + failed)));
-        returnObj.push_back(Pair("detail", resultsObj));
+        bool result = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage, mnb);
 
-        return returnObj;
+        Object statusObj;
+        statusObj.push_back(Pair("alias", mne.getAlias()));
+        statusObj.push_back(Pair("result", result ? "successful" : "failed"));
+
+        if (result) {
+            successful++;
+            mnodeman.UpdateMasternodeList(mnb);
+            mnb.Relay();
+        } else {
+            failed++;
+            statusObj.push_back(Pair("errorMessage", errorMessage));
+        }
+
+        resultsObj.push_back(Pair("status", statusObj));
     }
 
+    Object returnObj;
+    returnObj.push_back(Pair("overall", strprintf("Successfully started %d masternodes, failed to start %d, total %d", successful, failed, successful + failed)));
+    returnObj.push_back(Pair("detail", resultsObj));
+
+    return returnObj;
+}
+
+
     if (strCommand == "create")
     {
 
@@ -637,15 +681,25 @@ Value masternodebroadcast(const Array& params, bool fHelp)
         statusObj.push_back(Pair("alias", alias));
 
         BOOST_FOREACH(CNodeEntry mne, masternodeConfig.getEntries()) {
-            if(mne.getAlias() == alias) {
+            if (mne.getAlias() == alias) {
                 found = true;
                 std::string errorMessage;
                 CMasternodeBroadcast mnb;
 
+                // Extract the IP address from the configuration
+                CService addr(mne.getIp());
+
+                // Check if the IP address is already in use by another masternode
+                if (mnodeman.IsAddressInUse(addr)) {
+                    statusObj.push_back(Pair("result", "failed"));
+                    statusObj.push_back(Pair("errorMessage", "IP address is already in use by another masternode."));
+                    break; // Exit the loop as we found a conflict
+                }
+
                 bool result = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage, mnb, true);
 
                 statusObj.push_back(Pair("result", result ? "successful" : "failed"));
-                if(result) {
+                if (result) {
                     vecMnb.push_back(mnb);
                     CDataStream ssVecMnb(SER_NETWORK, PROTOCOL_VERSION);
                     ssVecMnb << vecMnb;
@@ -657,13 +711,12 @@ Value masternodebroadcast(const Array& params, bool fHelp)
             }
         }
 
-        if(!found) {
-            statusObj.push_back(Pair("result", "not found"));
-            statusObj.push_back(Pair("errorMessage", "Could not find alias in config. Verify with list-conf."));
+        if (!found) {
+            statusObj.push_back(Pair("result", "failed"));
+            statusObj.push_back(Pair("errorMessage", "Alias not found."));
         }
 
         return statusObj;
-
     }
 
     if (strCommand == "create-all")
@@ -692,6 +745,20 @@ Value masternodebroadcast(const Array& params, bool fHelp)
             CTxIn vin = CTxIn(uint256S(mne.getTxHash()), uint32_t(atoi(mne.getOutputIndex().c_str())));
             CMasternodeBroadcast mnb;
 
+            // Extract the IP address from the configuration
+            CService addr(mne.getIp());
+
+            // Check if the IP address is already in use by another masternode
+            if (mnodeman.IsAddressInUse(addr)) {
+                failed++;
+                Object statusObj;
+                statusObj.push_back(Pair("alias", mne.getAlias()));
+                statusObj.push_back(Pair("result", "failed"));
+                statusObj.push_back(Pair("errorMessage", "IP address is already in use by another masternode."));
+                resultsObj.push_back(Pair("status", statusObj));
+                continue; // Skip to the next entry
+            }
+
             bool result = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage, mnb, true);
 
             Object statusObj;
diff --git a/src/rpcsystemnode.cpp b/src/rpcsystemnode.cpp
index 9b9821f14..d09a515e5 100644
--- a/src/rpcsystemnode.cpp
+++ b/src/rpcsystemnode.cpp
@@ -1,11 +1,14 @@
 // Copyright (c) 2010 Satoshi Nakamoto
 // Copyright (c) 2009-2012 The Bitcoin developers
+// Copyright (c) 2014-2015 The Dash developers
+// Copyright (c) 2014-2018 The Crown developers
 // Distributed under the MIT/X11 software license, see the accompanying
 // file COPYING or http://www.opensource.org/licenses/mit-license.php.
 
 #include "main.h"
 #include "db.h"
 #include "init.h"
+#include "net.h"
 #include "systemnodeconfig.h"
 #include "systemnode.h"
 #include "systemnodeman.h"
@@ -15,6 +18,7 @@
 #include "wallet.h"
 #include "key.h"
 #include "base58.h"
+#include "netbase.h"
 
 #include <fstream>
 #include <string>
@@ -54,6 +58,7 @@ Value systemnode(const Array& params, bool fHelp)
                 "\nAvailable commands:\n"
                 "  count        - Print number of all known systemnodes (optional: 'ds', 'enabled', 'all', 'qualify')\n"
                 "  current      - Print info on current systemnode winner\n"
+                "  connect      - Test the connection to a Systemnode using node collateral address\n"
                 "  debug        - Print systemnode status\n"
                 "  enforce      - Enforce systemnode payments\n"
                 "  outputs      - Print systemnode compatible outputs\n"
@@ -78,7 +83,7 @@ Value systemnode(const Array& params, bool fHelp)
         return "Show budgets";
     }
 
-    if(strCommand == "connect")
+    if (strCommand == "connect")
     {
         std::string strAddress = "";
         if (params.size() == 2) {
@@ -87,14 +92,21 @@ Value systemnode(const Array& params, bool fHelp)
             throw runtime_error("Systemnode address required\n");
         }
 
-        CService addr = CService(strAddress);
+        CService addr;
+        try {
+            addr = CService(strAddress);
+        } catch (const std::exception &e) {
+            throw runtime_error("Invalid address format: " + std::string(e.what()) + "\n");
+        } catch (...) {
+            throw runtime_error("An unknown error occurred while parsing the address\n");
+        }
 
         CNode *pnode = ConnectNode((CAddress)addr, NULL, false);
-        if(pnode){
+        if (pnode) {
             pnode->Release();
-            return "successfully connected";
+            return "Successfully connected to " + addr.ToString();
         } else {
-            throw runtime_error("error connecting\n");
+            throw runtime_error("Error connecting to " + addr.ToString() + "\n");
         }
     }
 
@@ -177,52 +189,60 @@ Value systemnode(const Array& params, bool fHelp)
         return activeSystemnode.GetStatus();
     }
 
-    if (strCommand == "start-alias")
-    {
-        if (params.size() < 2){
-            throw runtime_error("command needs at least 2 parameters\n");
-        }
+if (strCommand == "start-alias")
+{
+    if (params.size() < 2) {
+        throw runtime_error("command needs at least 2 parameters\n");
+    }
 
-        {
-            LOCK(pwalletMain->cs_wallet);
-            EnsureWalletIsUnlocked();
-        }
+    {
+        LOCK(pwalletMain->cs_wallet);
+        EnsureWalletIsUnlocked();
+    }
 
-        std::string alias = params[1].get_str();
+    std::string alias = params[1].get_str();
 
-        bool found = false;
+    bool found = false;
 
-        Object statusObj;
-        statusObj.push_back(Pair("alias", alias));
+    Object statusObj;
+    statusObj.push_back(Pair("alias", alias));
 
-        BOOST_FOREACH(CNodeEntry mne, systemnodeConfig.getEntries()) {
-            if(mne.getAlias() == alias) {
-                found = true;
-                std::string errorMessage;
-                CSystemnodeBroadcast snb;
+    BOOST_FOREACH(CNodeEntry mne, systemnodeConfig.getEntries()) {
+        if (mne.getAlias() == alias) {
+            found = true;
+            std::string errorMessage;
+            CSystemnodeBroadcast snb;
 
-                bool result = CSystemnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage, snb);
+            CService addr(mne.getIp());
+            // Check if the IP address is already in use by another systemnode
 
-                statusObj.push_back(Pair("result", result ? "successful" : "failed"));
-                if(result) {
-                    snodeman.UpdateSystemnodeList(snb);
-                    snb.Relay();
-                } else {
-                    statusObj.push_back(Pair("errorMessage", errorMessage));
-                }
-                break;
+            if (snodeman.IsAddressInUse(addr)) {
+                statusObj.push_back(Pair("result", "failed"));
+                statusObj.push_back(Pair("errorMessage", "IP address is already in use by another systemnode."));
+                return statusObj;
             }
-        }
 
-        if(!found) {
-            statusObj.push_back(Pair("result", "failed"));
-            statusObj.push_back(Pair("errorMessage", "could not find alias in config. Verify with list-conf."));
-        }
+            bool result = CSystemnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage, snb);
 
-        return statusObj;
+            statusObj.push_back(Pair("result", result ? "successful" : "failed"));
+            if (result) {
+                snodeman.UpdateSystemnodeList(snb);
+                snb.Relay();
+            } else {
+                statusObj.push_back(Pair("errorMessage", errorMessage));
+            }
+            break;
+        }
+    }
 
+    if (!found) {
+        statusObj.push_back(Pair("result", "failed"));
+        statusObj.push_back(Pair("errorMessage", "could not find alias in config. Verify with list-conf."));
     }
 
+    return statusObj;
+}
+
     if (strCommand == "create")
     {
 
@@ -274,9 +294,9 @@ Value systemnode(const Array& params, bool fHelp)
             EnsureWalletIsUnlocked();
         }
 
-        if((strCommand == "start-missing" || strCommand == "start-disabled") &&
-         (systemnodeSync.RequestedSystemnodeAssets <= SYSTEMNODE_SYNC_LIST ||
-          systemnodeSync.RequestedSystemnodeAssets == SYSTEMNODE_SYNC_FAILED)) {
+        if ((strCommand == "start-missing" || strCommand == "start-disabled") &&
+            (systemnodeSync.RequestedSystemnodeAssets <= SYSTEMNODE_SYNC_LIST ||
+            systemnodeSync.RequestedSystemnodeAssets == SYSTEMNODE_SYNC_FAILED)) {
             throw runtime_error("You can't use this command until systemnode list is synced\n");
         }
 
@@ -292,11 +312,23 @@ Value systemnode(const Array& params, bool fHelp)
             std::string errorMessage;
 
             CTxIn vin = CTxIn(uint256S(mne.getTxHash()), uint32_t(atoi(mne.getOutputIndex().c_str())));
-            CSystemnode *pmn = snodeman.Find(vin);
+            CSystemnode *psn = snodeman.Find(vin);
             CSystemnodeBroadcast snb;
 
-            if(strCommand == "start-missing" && pmn) continue;
-            if(strCommand == "start-disabled" && pmn && pmn->IsEnabled()) continue;
+            if (strCommand == "start-missing" && psn) continue;
+            if (strCommand == "start-disabled" && psn && psn->IsEnabled()) continue;
+
+            CService addr(mne.getIp());
+            // Check if the IP address is already in use by another systemnode
+            if (snodeman.IsAddressInUse(addr)) {
+                failed++;
+                Object statusObj;
+                statusObj.push_back(Pair("alias", mne.getAlias()));
+                statusObj.push_back(Pair("result", "failed"));
+                statusObj.push_back(Pair("errorMessage", "IP address is already in use by another systemnode."));
+                resultsObj.push_back(Pair("status", statusObj));
+                continue; // Skip to the next entry
+            }
 
             bool result = CSystemnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage, snb);
 
@@ -304,7 +336,7 @@ Value systemnode(const Array& params, bool fHelp)
             statusObj.push_back(Pair("alias", mne.getAlias()));
             statusObj.push_back(Pair("result", result ? "successful" : "failed"));
 
-            if(result) {
+            if (result) {
                 successful++;
                 snodeman.UpdateSystemnodeList(snb);
                 snb.Relay();
@@ -323,6 +355,7 @@ Value systemnode(const Array& params, bool fHelp)
         return returnObj;
     }
 
+
     if(strCommand == "status")
     {
         if(!fSystemNode) throw runtime_error("This is not a systemnode\n");
@@ -547,7 +580,7 @@ Value systemnodebroadcast(const Array& params, bool fHelp)
         bool found = false;
 
         Object statusObj;
-        std::vector<CSystemnodeBroadcast> vecMnb;
+        std::vector<CSystemnodeBroadcast> vecSnb;
 
         statusObj.push_back(Pair("alias", alias));
 
@@ -557,14 +590,23 @@ Value systemnodebroadcast(const Array& params, bool fHelp)
                 std::string errorMessage;
                 CSystemnodeBroadcast snb;
 
+                CService addr(mne.getIp());
+                // Check if the IP address is already in use by another systemnode
+
+                if (snodeman.IsAddressInUse(addr)) {
+                    statusObj.push_back(Pair("result", "failed"));
+                    statusObj.push_back(Pair("errorMessage", "IP address is already in use by another systemnode."));
+                    break; // Skip to the next entry
+                }
+
                 bool result = CSystemnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage, snb, true);
 
                 statusObj.push_back(Pair("result", result ? "successful" : "failed"));
                 if(result) {
-                    vecMnb.push_back(snb);
-                    CDataStream ssVecMnb(SER_NETWORK, PROTOCOL_VERSION);
-                    ssVecMnb << vecMnb;
-                    statusObj.push_back(Pair("hex", HexStr(ssVecMnb.begin(), ssVecMnb.end())));
+                    vecSnb.push_back(snb);
+                    CDataStream ssVecSnb(SER_NETWORK, PROTOCOL_VERSION);
+                    ssVecSnb << vecSnb;
+                    statusObj.push_back(Pair("hex", HexStr(ssVecSnb.begin(), ssVecSnb.end())));
                 } else {
                     statusObj.push_back(Pair("errorMessage", errorMessage));
                 }
@@ -578,9 +620,9 @@ Value systemnodebroadcast(const Array& params, bool fHelp)
         }
 
         return statusObj;
-
     }
 
+
     if (strCommand == "create-all")
     {
         // wait for reindex and/or import to finish
@@ -599,7 +641,7 @@ Value systemnodebroadcast(const Array& params, bool fHelp)
         int failed = 0;
 
         Object resultsObj;
-        std::vector<CSystemnodeBroadcast> vecMnb;
+        std::vector<CSystemnodeBroadcast> vecSnb;
 
         BOOST_FOREACH(CNodeEntry mne, systemnodeConfig.getEntries()) {
             std::string errorMessage;
@@ -607,6 +649,19 @@ Value systemnodebroadcast(const Array& params, bool fHelp)
             CTxIn vin = CTxIn(uint256S(mne.getTxHash()), uint32_t(atoi(mne.getOutputIndex().c_str())));
             CSystemnodeBroadcast snb;
 
+            // Check if the IP address is already in use by another systemnode
+            CService addr(mne.getIp());
+
+            if (snodeman.IsAddressInUse(addr)) {
+                failed++;
+                Object statusObj;
+                statusObj.push_back(Pair("alias", mne.getAlias()));
+                statusObj.push_back(Pair("result", "failed"));
+                statusObj.push_back(Pair("errorMessage", "IP address is already in use by another systemnode."));
+                resultsObj.push_back(Pair("status", statusObj));
+                continue; // Skip to the next entry
+            }
+
             bool result = CSystemnodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), errorMessage, snb, true);
 
             Object statusObj;
@@ -615,7 +670,7 @@ Value systemnodebroadcast(const Array& params, bool fHelp)
 
             if(result) {
                 successful++;
-                vecMnb.push_back(snb);
+                vecSnb.push_back(snb);
             } else {
                 failed++;
                 statusObj.push_back(Pair("errorMessage", errorMessage));
@@ -624,16 +679,17 @@ Value systemnodebroadcast(const Array& params, bool fHelp)
             resultsObj.push_back(Pair("status", statusObj));
         }
 
-        CDataStream ssVecMnb(SER_NETWORK, PROTOCOL_VERSION);
-        ssVecMnb << vecMnb;
+        CDataStream ssVecSnb(SER_NETWORK, PROTOCOL_VERSION);
+        ssVecSnb << vecSnb;
         Object returnObj;
         returnObj.push_back(Pair("overall", strprintf("Successfully created broadcast messages for %d systemnodes, failed to create %d, total %d", successful, failed, successful + failed)));
         returnObj.push_back(Pair("detail", resultsObj));
-        returnObj.push_back(Pair("hex", HexStr(ssVecMnb.begin(), ssVecMnb.end())));
+        returnObj.push_back(Pair("hex", HexStr(ssVecSnb.begin(), ssVecSnb.end())));
 
         return returnObj;
     }
 
+
     if (strCommand == "decode")
     {
         if (params.size() != 2)
diff --git a/src/systemnode.cpp b/src/systemnode.cpp
index 0553df60c..e32720ebe 100644
--- a/src/systemnode.cpp
+++ b/src/systemnode.cpp
@@ -421,7 +421,7 @@ bool CSystemnodeBroadcast::CheckAndUpdate(int& nDos) const
         return false;
     }
 
-    if(protocolVersion < systemnodePayments.GetMinSystemnodePaymentsProto()) {
+    if (protocolVersion < systemnodePayments.GetMinSystemnodePaymentsProto()) {
         LogPrintf("snb - ignoring outdated systemnode %s protocol version %d\n", vin.ToString(), protocolVersion);
         return false;
     }
@@ -429,7 +429,7 @@ bool CSystemnodeBroadcast::CheckAndUpdate(int& nDos) const
     CScript pubkeyScript;
     pubkeyScript = GetScriptForDestination(pubkey.GetID());
 
-    if(pubkeyScript.size() != 25) {
+    if (pubkeyScript.size() != 25) {
         LogPrintf("snb - pubkey the wrong size\n");
         nDos = 100;
         return false;
@@ -438,46 +438,45 @@ bool CSystemnodeBroadcast::CheckAndUpdate(int& nDos) const
     CScript pubkeyScript2;
     pubkeyScript2 = GetScriptForDestination(pubkey2.GetID());
 
-    if(pubkeyScript2.size() != 25) {
+    if (pubkeyScript2.size() != 25) {
         LogPrintf("snb - pubkey2 the wrong size\n");
         nDos = 100;
         return false;
     }
 
-    if(!vin.scriptSig.empty()) {
-        LogPrintf("snb - Ignore Not Empty ScriptSig %s\n",vin.ToString());
+    if (!vin.scriptSig.empty()) {
+        LogPrintf("snb - Ignore Not Empty ScriptSig %s\n", vin.ToString());
         return false;
     }
 
     // incorrect ping or its sigTime
-    if(lastPing == CSystemnodePing() || !lastPing.CheckAndUpdate(nDos, false, true))
+    if (lastPing == CSystemnodePing() || !lastPing.CheckAndUpdate(nDos, false, true))
         return false;
 
     std::string strMessage;
     std::string errorMessage = "";
 
-    if(protocolVersion <= 99999999) {
+    if (protocolVersion <= 99999999) {
         std::string vchPubKey(pubkey.begin(), pubkey.end());
         std::string vchPubKey2(pubkey2.begin(), pubkey2.end());
         strMessage = addr.ToString(false) + boost::lexical_cast<std::string>(sigTime) +
-                        vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);
+                     vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);
 
         LogPrint("systemnode", "snb - sanitized strMessage: %s, pubkey address: %s, sig: %s\n",
-            SanitizeString(strMessage), CBitcoinAddress(pubkey.GetID()).ToString(),
-            EncodeBase64(&sig[0], sig.size()));
+                 SanitizeString(strMessage), CBitcoinAddress(pubkey.GetID()).ToString(),
+                 EncodeBase64(&sig[0], sig.size()));
 
-        if(!legacySigner.VerifyMessage(pubkey, sig, strMessage, errorMessage)){
-            if (addr.ToString() != addr.ToString(false))
-            {
+        if (!legacySigner.VerifyMessage(pubkey, sig, strMessage, errorMessage)) {
+            if (addr.ToString() != addr.ToString(false)) {
                 // maybe it's wrong format, try again with the old one
                 strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
-                                vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);
+                             vchPubKey + vchPubKey2 + boost::lexical_cast<std::string>(protocolVersion);
 
                 LogPrint("systemnode", "snb - sanitized strMessage: %s, pubkey address: %s, sig: %s\n",
-                    SanitizeString(strMessage), CBitcoinAddress(pubkey.GetID()).ToString(),
-                    EncodeBase64(&sig[0], sig.size()));
+                         SanitizeString(strMessage), CBitcoinAddress(pubkey.GetID()).ToString(),
+                         EncodeBase64(&sig[0], sig.size()));
 
-                if(!legacySigner.VerifyMessage(pubkey, sig, strMessage, errorMessage)){
+                if (!legacySigner.VerifyMessage(pubkey, sig, strMessage, errorMessage)) {
                     // didn't work either
                     LogPrintf("snb - Got bad systemnode address signature, sanitized error: %s\n", SanitizeString(errorMessage));
                     // there is a bug in old MN signatures, ignore such MN but do not ban the peer we got this from
@@ -492,95 +491,121 @@ bool CSystemnodeBroadcast::CheckAndUpdate(int& nDos) const
         }
     } else {
         strMessage = addr.ToString(false) + boost::lexical_cast<std::string>(sigTime) +
-                        pubkey.GetID().ToString() + pubkey2.GetID().ToString() +
-                        boost::lexical_cast<std::string>(protocolVersion);
+                     pubkey.GetID().ToString() + pubkey2.GetID().ToString() +
+                     boost::lexical_cast<std::string>(protocolVersion);
 
         LogPrint("systemnode", "snb - strMessage: %s, pubkey address: %s, sig: %s\n",
-            strMessage, CBitcoinAddress(pubkey.GetID()).ToString(), EncodeBase64(&sig[0], sig.size()));
+                 strMessage, CBitcoinAddress(pubkey.GetID()).ToString(), EncodeBase64(&sig[0], sig.size()));
 
-        if(!legacySigner.VerifyMessage(pubkey, sig, strMessage, errorMessage)){
+        if (!legacySigner.VerifyMessage(pubkey, sig, strMessage, errorMessage)) {
             LogPrintf("snb - Got bad systemnode address signature, error: %s\n", errorMessage);
             nDos = 100;
             return false;
         }
     }
 
-    if(Params().NetworkID() == CBaseChainParams::MAIN) {
-        if(addr.GetPort() != 9340) return false;
-    } else if(addr.GetPort() == 9340) return false;
+    if (Params().NetworkID() == CBaseChainParams::MAIN) {
+        if (addr.GetPort() != 9340) return false;
+    } else if (addr.GetPort() == 9340) return false;
+
+    // Check if the IP address is already in use by another enabled systemnode
+    CSystemnode* psn = snodeman.Find(addr);
+
+    // Check if the IPv4 address is found and the vin obtained from the corresponding IPv4 address
+    // does not match the vin of the systemnode attempting to broadcast
+    if (psn && psn->vin != vin) {
+        // Check if the found systemnode is enabled and online
+        if (psn->IsEnabled()) {
+            // Check if the signing time of the new broadcast is later than the signing time of the initial broadcast
+            // to enable the found systemnode. If the new broadcast is more recent, it could be malicious and should be banned.
+            if (sigTime > psn->sigTime) {
+                LogPrintf("CSystemnodeBroadcast::CheckAndUpdate -- IP address already in use by another enabled systemnode %s\n", addr.ToString());
+                // Increment DoS score for duplicate IP
+                nDoS = 33;
+                // Stop the node from broadcasting and ultimately enforce unique IPv4
+                return false;
+            }
+        }
+    }
 
-    //search existing systemnode list, this is where we update existing Systemnodes with new snb broadcasts
+    // search existing systemnode list, this is where we update existing Systemnodes with new snb broadcasts
     CSystemnode* psn = snodeman.Find(vin);
 
     // no such systemnode, nothing to update
-    if(psn == NULL) return true;
+    if (psn == NULL) return true;
 
-    // this broadcast is older or equal than the one that we already have - it's bad and should never happen
+    // this broadcast is older or equal to the one that we already have - it's bad and should never happen
     // unless someone is doing something fishy
-    // (mapSeensystemnodeBroadcast in CSystemnodeMan::ProcessMessage should filter legit duplicates)
-    if(psn->sigTime >= sigTime) {
-        LogPrintf("CsystemnodeBroadcast::CheckAndUpdate - Bad sigTime %d for Systemnode %20s %105s (existing broadcast is at %d)\n",
-                      sigTime, addr.ToString(), vin.ToString(), psn->sigTime);
+    // (mapSeenSystemnodeBroadcast in CSystemnodeMan::ProcessMessage should filter legit duplicates)
+    if (psn->sigTime >= sigTime) {
+        LogPrintf("CSystemnodeBroadcast::CheckAndUpdate - Bad sigTime %d for Systemnode %20s %105s (existing broadcast is at %d)\n",
+                  sigTime, addr.ToString(), vin.ToString(), psn->sigTime);
         return false;
     }
 
     // systemnode is not enabled yet/already, nothing to update
-    if(!psn->IsEnabled()) return true;
+    if (!psn->IsEnabled()) return true;
 
     // sn.pubkey = pubkey, IsVinAssociatedWithPubkey is validated once below,
     //   after that they just need to match
-    if(psn->pubkey == pubkey && !psn->IsBroadcastedWithin(SYSTEMNODE_MIN_SNB_SECONDS)) {
-        //take the newest entry
+    if (psn->pubkey == pubkey && !psn->IsBroadcastedWithin(SYSTEMNODE_MIN_SNB_SECONDS)) {
+        // take the newest entry
         LogPrintf("snb - Got updated entry for %s\n", addr.ToString());
-        if(psn->UpdateFromNewBroadcast((*this))){
+        if (psn->UpdateFromNewBroadcast((*this))) {
             psn->Check();
-            if(psn->IsEnabled()) Relay();
+            if (psn->IsEnabled()) Relay();
         }
         systemnodeSync.AddedSystemnodeList(GetHash());
     }
 
     return true;
-
 }
 
 bool CSystemnodeBroadcast::CheckInputsAndAdd(int& nDoS) const
 {
     // we are a systemnode with the same vin (i.e. already activated) and this snb is ours (matches our systemnode privkey)
     // so nothing to do here for us
-    if(fSystemNode && vin.prevout == activeSystemnode.vin.prevout && pubkey2 == activeSystemnode.pubKeySystemnode)
+    if (fSystemNode && vin.prevout == activeSystemnode.vin.prevout && pubkey2 == activeSystemnode.pubKeySystemnode)
         return true;
 
     // incorrect ping or its sigTime
-    if(lastPing == CSystemnodePing() || !lastPing.CheckAndUpdate(nDoS, false, true))
+    if (lastPing == CSystemnodePing() || !lastPing.CheckAndUpdate(nDoS, false, true))
         return false;
 
     // search existing systemnode list
     CSystemnode* psn = snodeman.Find(vin);
 
-    if(psn != NULL) {
+    if (psn != NULL) {
         // nothing to do here if we already know about this systemnode and it's enabled
-        if(psn->IsEnabled()) return true;
-        // if it's not enabled, remove old MN first and continue
+        if (psn->IsEnabled()) return true;
+        // if it's not enabled, remove old SN first and continue
         else snodeman.Remove(psn->vin);
     }
 
+    // Check if the IP address is already in use
+    if (snodeman.IsAddressInUse(addr)) {
+        LogPrintf("CSystemnodeBroadcast::CheckInputsAndAdd -- IP address already in use %s\n", addr.ToString());
+        nDoS = 33;  // Increment DoS score for duplicate IP
+        return false;
+    }
+
     CValidationState state;
     CMutableTransaction tx = CMutableTransaction();
-    CTxOut vout = CTxOut((SYSTEMNODE_COLLATERAL - 0.01)*COIN, legacySigner.collateralPubKey);
+    CTxOut vout = CTxOut((SYSTEMNODE_COLLATERAL - 0.01) * COIN, legacySigner.collateralPubKey);
     tx.vin.push_back(vin);
     tx.vout.push_back(vout);
 
     {
         TRY_LOCK(cs_main, lockMain);
-        if(!lockMain) {
+        if (!lockMain) {
             // not snb fault, let it to be checked again later
             snodeman.mapSeenSystemnodeBroadcast.erase(GetHash());
             systemnodeSync.mapSeenSyncSNB.erase(GetHash());
             return false;
         }
 
-        if(!AcceptableInputs(mempool, state, CTransaction(tx), false, NULL)) {
-            //set nDos
+        if (!AcceptableInputs(mempool, state, CTransaction(tx), false, NULL)) {
+            // set nDos
             state.IsInvalid(nDoS);
             return false;
         }
@@ -588,26 +613,24 @@ bool CSystemnodeBroadcast::CheckInputsAndAdd(int& nDoS) const
 
     LogPrint("systemnode", "snb - Accepted systemnode entry\n");
 
-    if(GetInputAge(vin) < SYSTEMNODE_MIN_CONFIRMATIONS){
+    if (GetInputAge(vin) < SYSTEMNODE_MIN_CONFIRMATIONS) {
         LogPrintf("snb - Input must have at least %d confirmations\n", SYSTEMNODE_MIN_CONFIRMATIONS);
-        // maybe we miss few blocks, let this snb to be checked again later
+        // maybe we miss a few blocks, let this snb be checked again later
         snodeman.mapSeenSystemnodeBroadcast.erase(GetHash());
         systemnodeSync.mapSeenSyncSNB.erase(GetHash());
         return false;
     }
 
-    // verify that sig time is legit in past
+    // verify that sig time is legit in the past
     // should be at least not earlier than block when 10000 CRW tx got SYSTEMNODE_MIN_CONFIRMATIONS
     uint256 hashBlock = uint256();
     CTransaction tx2;
     GetTransaction(vin.prevout.hash, tx2, hashBlock, true);
     BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
-    if (mi != mapBlockIndex.end() && (*mi).second)
-    {
+    if (mi != mapBlockIndex.end() && (*mi).second) {
         CBlockIndex* pMNIndex = (*mi).second; // block for 10000 CRW tx -> 1 confirmation
         CBlockIndex* pConfIndex = chainActive[pMNIndex->nHeight + SYSTEMNODE_MIN_CONFIRMATIONS - 1]; // block where tx got SYSTEMNODE_MIN_CONFIRMATIONS
-        if(pConfIndex->GetBlockTime() > sigTime)
-        {
+        if (pConfIndex->GetBlockTime() > sigTime) {
             LogPrintf("snb - Bad sigTime %d for systemnode %20s %105s (%i conf block is at %d)\n",
                       sigTime, addr.ToString(), vin.ToString(), SYSTEMNODE_MIN_CONFIRMATIONS, pConfIndex->GetBlockTime());
             return false;
@@ -619,7 +642,7 @@ bool CSystemnodeBroadcast::CheckInputsAndAdd(int& nDoS) const
     snodeman.Add(sn);
 
     // if it matches our systemnode privkey, then we've been remotely activated
-    if(pubkey2 == activeSystemnode.pubKeySystemnode && protocolVersion == PROTOCOL_VERSION){
+    if (pubkey2 == activeSystemnode.pubKeySystemnode && protocolVersion == PROTOCOL_VERSION) {
         activeSystemnode.EnableHotColdSystemNode(vin, addr);
         if (!vchSignover.empty()) {
             if (pubkey.Verify(pubkey2.GetHash(), vchSignover)) {
@@ -631,18 +654,17 @@ bool CSystemnodeBroadcast::CheckInputsAndAdd(int& nDoS) const
         } else {
             LogPrintf("%s: NOT SIGNOVER!\n", __func__);
         }
-
     }
 
     bool isLocal = addr.IsRFC1918() || addr.IsLocal();
-    if(Params().NetworkID() == CBaseChainParams::REGTEST) isLocal = false;
+    if (Params().NetworkID() == CBaseChainParams::REGTEST) isLocal = false;
 
-    if(!isLocal) Relay();
+    if (!isLocal) Relay();
 
     return true;
-
 }
 
+
 void CSystemnodeBroadcast::Relay() const
 {
     CInv inv(MSG_SYSTEMNODE_ANNOUNCE, GetHash());
diff --git a/src/systemnodeman.cpp b/src/systemnodeman.cpp
index 4b7b1a507..4526498d7 100644
--- a/src/systemnodeman.cpp
+++ b/src/systemnodeman.cpp
@@ -263,6 +263,20 @@ bool CSystemnodeMan::CheckSnbAndUpdateSystemnodeList(CSystemnodeBroadcast snb, i
     return true;
 }
 
+CSystemnode* CSystemnodeMan::Find(const CScript &payee)
+{
+    LOCK(cs);
+    CScript payee2;
+
+    BOOST_FOREACH(CSystemnode& sn, vSystemnodes)
+    {
+        payee2 = GetScriptForDestination(sn.pubkey.GetID());
+        if(payee2 == payee)
+            return &sn;
+    }
+    return NULL;
+}
+
 CSystemnode *CSystemnodeMan::Find(const CTxIn &vin)
 {
     LOCK(cs);
@@ -451,6 +465,17 @@ void CSystemnodeMan::DsegUpdate(CNode* pnode)
     mWeAskedForSystemnodeList[pnode->addr] = askAgain;
 }
 
+bool CSystemnodeMan::IsAddressInUse(const CService& addr)
+{
+    LOCK(cs);
+    for (const auto& sn : vSystemnodes) {
+        if (sn.addr == addr) {
+            return true;
+        }
+    }
+    return false;
+}
+
 std::string CSystemnodeMan::ToString() const
 {
     std::ostringstream info;
@@ -489,23 +514,25 @@ CSystemnode* CSystemnodeMan::GetCurrentSystemNode(int mod, int64_t nBlockHeight,
     CSystemnode* winner = NULL;
 
     // scan for winner
-    BOOST_FOREACH(CSystemnode& mn, vSystemnodes) {
-        mn.Check();
-        if(mn.protocolVersion < minProtocol || !mn.IsEnabled()) continue;
+    BOOST_FOREACH(CSystemnode& sn, vSystemnodes) {
+        sn.Check();
+        if(sn.protocolVersion < minProtocol || !sn.IsEnabled()) continue;
 
         // calculate the score for each Systemnode
-        int64_t n2 = mn.CalculateScore(nBlockHeight).GetCompact(false);
+        arith_uint256 n = sn.CalculateScore(nBlockHeight);
+        int64_t n2 = n.GetCompact(false);
 
         // determine the winner
         if(n2 > score){
             score = n2;
-            winner = &mn;
+            winner = &sn;
         }
     }
 
     return winner;
 }
 
+
 int CSystemnodeMan::GetSystemnodeRank(const CTxIn& vin, int64_t nBlockHeight, int minProtocol, bool fOnlyActive)
 {
     std::vector<pair<int64_t, CTxIn> > vecSystemnodeScores;
diff --git a/src/systemnodeman.h b/src/systemnodeman.h
index 309675192..9a2f27433 100644
--- a/src/systemnodeman.h
+++ b/src/systemnodeman.h
@@ -82,7 +82,11 @@ public:
 
     void DsegUpdate(CNode* pnode);
 
+    /// Check if an IP address is already in use by another systemnode
+    bool IsAddressInUse(const CService& addr);
+
     /// Find an entry
+    CSystemnode* Find(const CScript &payee);
     CSystemnode* Find(const CTxIn& vin);
     CSystemnode* Find(const CPubKey& pubKeySystemnode);
     CSystemnode* Find(const CService& addr);
```

### Did later revival work modify the same lines?
**Yes.**

Later revival commit `fd810b6a00217f6d5e856963a6cc760e664e5fac` edited PR #1-introduced lines in:
- `src/masternode.cpp`
- `src/systemnode.cpp`

Specifically, it renamed the PR #1-added local variables (`pmn`/`psn` -> `pmnByAddr`/`psnByAddr`) and corrected `nDoS` -> `nDos` in `CheckAndUpdate` blocks.

---

## 2) Clean 0.14.0.4 baseline

Using upstream `Crowndev/crown-core` metadata fetched locally:
- **Tag/version:** `v0.14.0.4`
- **Upstream SHA:** `3050c1f970e6dc4713c41a88f80638c597af33e9`
- **Tag/commit date:** `2023-08-02 16:40:22 +0200`

Merge-base checks:
- `merge-base(v0.14.0.4, 2fcf128252b2710a2cd7028d44ff4ca02d519cfe) = 3050c1f970e6dc4713c41a88f80638c597af33e9`
- `merge-base(v0.14.0.4, 487053abf22c7bacdfad80fad1081f856db9b940) = 3050c1f970e6dc4713c41a88f80638c597af33e9`

Comparison:
- `v0.14.0.4..2fcf128...` changes only `scripts/crown-server-install.sh` (non-production script path).
- `v0.14.0.4..487053...` adds PR #1 production changes plus the same script delta.

### Is PR #1 the ONLY production-source difference vs clean 0.14.0.4?
**YES** (for production source paths under `src/` when using the PR #1-era pre-revival state).

Non-production extra delta present in that era:
- `scripts/crown-server-install.sh`

---

## 3) What PR #1 actually does

### A. Monetary range constant
- **Previous behaviour:** Transaction/fee value range checks used `MAX_MONEY = 21,000,000 * COIN`.
- **Behaviour introduced:** Range checks now allow values up to `42,000,000 * COIN`.
- **Likely intent:** Align hard ceiling with a presumed Crown supply target.
- **Trigger condition:** Any code path calling `MoneyRange(...)` on large values.
- **Impact areas:**
  - consensus / block validation: **POSSIBLE**
  - monetary behaviour: **YES**
  - wallet behaviour: **POSSIBLE**

### B. Duplicate IPv4 rejection in MN/SN broadcast acceptance
- **Previous behaviour:** MN/SN broadcast acceptance did not uniformly reject duplicate service addresses across different vins.
- **Behaviour introduced:** Added `IsAddressInUse(...)` checks and pre-checks by address in:
  - MN: `CheckAndUpdate`, `CheckInputsAndAdd`
  - SN: `CheckAndUpdate`, `CheckInputsAndAdd`
  - manager helpers: `CMasternodeMan::IsAddressInUse`, `CSystemnodeMan::IsAddressInUse`
- **Likely intent:** Enforce unique IPv4 per active MN/SN.
- **Trigger condition:** Broadcast or start/broadcast RPC involving an address already present in node lists.
- **Impact areas:**
  - Masternodes: **YES**
  - Systemnodes: **YES**
  - MNPoS/payment state: **POSSIBLE** (registration and payee-set side effects)
  - P2P/wire behaviour: **YES** (reject/DoS-score on some duplicate-address cases)

### C. RPC/UI address checks and connect UX changes
- **Previous behaviour:** `connect` handlers used direct parse/connection flow; start/broadcast paths did not pre-fail on local duplicate-address list checks.
- **Behaviour introduced:**
  - Added parse guard try/catch and message text changes for `connect` in MN/SN RPC.
  - Added duplicate-IP prechecks in `masternode`, `systemnode`, `masternodebroadcast`, `systemnodebroadcast` start/create flows.
  - Added duplicate-IP guard in Qt `CreateNodeDialog::CheckIP()`.
- **Likely intent:** Fail early for obvious address conflicts and improve operator-facing messaging.
- **Trigger condition:** CLI/UI attempts using already-known address, or malformed connect address.
- **Impact areas:**
  - wallet/operator behaviour: **YES**
  - address handling: **YES**
  - consensus: **NO (direct)**

### D. Minor manager/refactor additions
- Added `CSystemnodeMan::Find(const CScript&)` declaration/definition.
- Minor local variable extraction in `GetCurrentSystemNode(...)`.
- Mostly structural/supporting changes.

---

## 4) Correctness review and classification

- `MAX_MONEY` 21M -> 42M  
  - **Classification:** QUESTIONABLE  
  - **Evidence:** Consensus/monetary-adjacent rule change with no accompanying consensus test evidence in PR #1. The stated baseline tag `v0.14.0.4` uses `21,000,000 * COIN`, so PR #1 is an explicit monetary-rule deviation from the revival baseline.

- Duplicate-IP checks in `CheckInputsAndAdd` (MN/SN)  
  - **Classification:** QUESTIONABLE  
  - **Evidence:** Enforces uniqueness but uses `IsAddressInUse(addr)` without a same-identity (`vin`) exclusion in that guard path; admission can depend on local list state and produce false-positive conflicts. Actionable remediation: make duplicate checks identity-aware (`addr` + different `vin`) instead of address-only.

- Duplicate-IP checks in `CheckAndUpdate` (MN/SN) as originally merged  
  - **Classification:** QUESTIONABLE  
  - **Evidence:** The same lines required later corrective edits in revival commit `fd810b6a00217f6d5e856963a6cc760e664e5fac` (variable/identifier normalization in both MN and SN duplicate-IP branches), indicating the original change landed without sufficient hardening and needed follow-up repair.

- RPC/UI duplicate-IP prechecks  
  - **Classification:** QUESTIONABLE  
  - **Evidence:** Uses local in-memory list state as hard gate in start/create UX; can fail legitimate operator flows when local state is stale or self-overlapping from operator perspective.

- Added `Find(const CScript&)` and score-local refactor  
  - **Classification:** HARMLESS / REDUNDANT  
  - **Evidence:** No substantive behavioural change beyond helper availability and temporary variable extraction.

Additional review notes:
- Historical-vs-current scope note: current revival branch already includes corrective edits on PR #1 `CheckAndUpdate` duplicate-IP lines (commit `fd810b6a00217f6d5e856963a6cc760e664e5fac`); the audit classification here is historical assessment of the original PR payload quality, not a claim that those exact defects remain live today.
- No serialization-format changes were introduced by PR #1.
- No cryptographic primitive changes were introduced by PR #1.
- P2P handling is changed through additional reject/DoS-score paths in broadcast validation logic.

---

## 5) Relationship to revival findings

- Phase 1C: tCRW address validation/send issue  
  - **Relation:** UNRELATED  
  - **Why:** Phase 1C issue is base58/version-prefix mismatch in regtest address handling; PR #1 touches MN/SN duplicate-IP checks and MAX_MONEY, not base58 decode/version tables.

- Phase 1D: MNPoS bootstrap difficulties  
  - **Relation:** POSSIBLY RELATED  
  - **Why:** PR #1 affects MN/SN registration admission and local start/broadcast gating; this can influence practical bootstrap/operator flows, but does not alter PoS activation economics directly.

- Phase 1E: registration divergence  
  - **Relation:** POSSIBLY RELATED  
  - **Why:** PR #1 modifies `CSystemnodeBroadcast::CheckInputsAndAdd` and registration acceptance flow area, but deterministic repro still shows the same first divergence trigger (`sigTime`/15-conf timing check).

- Phase 1E: `GetValueOut` payment-transition failure  
  - **Relation:** UNRELATED  
  - **Why:** `GetValueOut` issue is coinbase output-slot/value construction; PR #1 does not touch payment-output construction paths that caused that failure.

- Phase 1F: systemnode-only coinbase placeholder fix  
  - **Relation:** UNRELATED  
  - **Why:** Phase 1F fix is in systemnode/masternode payment-output construction; PR #1 does not modify that output-slot logic.

---

## 6) With/without PR #1 test evidence

Temporary states used:
- **A (with PR #1):** current recovered branch build in repo working tree
- **B (without PR #1):** detached worktree `/tmp/crown-pr1-revert` created with:
  - `git worktree add /tmp/crown-pr1-revert HEAD`
  - `cd /tmp/crown-pr1-revert`
  - `git revert -m 1 --no-edit 487053abf22c7bacdfad80fad1081f856db9b940`
  - resolve two conflicts in `src/masternode.cpp` and `src/systemnode.cpp` by removing the PR #1 `CheckAndUpdate` duplicate-IP blocks, then:
  - `git add src/masternode.cpp src/systemnode.cpp && git revert --continue`

Builds:
- Both A and B built `src/crownd` and `src/crown-cli` successfully with:
  - `--with-incompatible-bdb`
  - `--with-unsupported-ssl`

Deterministic reproduction run (Phase 1E registration divergence script):
- Command A: `KEEP_WORKDIR=1 ./contrib/devtools/revival/repro-registration-divergence.sh /tmp/pr1-a-regdiv`
- Command B: `KEEP_WORKDIR=1 BIN_DIR=/tmp/crown-pr1-revert/src ./contrib/devtools/revival/repro-registration-divergence.sh /tmp/pr1-b-regdiv`
- Inline reproducible evidence captured from both runs (so `/tmp` cleanup is non-blocking):
  - Run A (`with PR #1`) terminal output:
    - `divergence reproduced`
    - `first divergent event=remote CheckInputsAndAdd sigTime check`
    - `7134:2026-09-11 21:26:03 snb - Bad sigTime 1789161963 for systemnode 8.8.8.8:24003 ... (15 conf block is at 1789162076)`
  - Run B (`PR #1 reverted`) terminal output:
    - `divergence reproduced`
    - `first divergent event=remote CheckInputsAndAdd sigTime check`
    - `7167:2026-09-11 21:33:10 snb - Bad sigTime 1789162390 for systemnode 8.8.8.8:24003 ... (15 conf block is at 1789162502)`

Observed outcome (both A and B):
- `systemnode start-alias sn1` returns success locally on `sn1`
- Remote peers remain at systemnode count `0`
- Divergence reproduced
- First remote rejection remains `Bad sigTime ... (15 conf block is at ...)`

Conclusion from with/without run:
- For this deterministic registration-divergence scenario, **no behavioural difference was observed** between A and B.
- The PR #1 duplicate-IP logic was not the deciding branch in this repro path.

---

## 7) Historical compatibility impact of reverting PR #1 now

Potential impacts if PR #1 is reverted:
- historical block validation: **POSSIBLE** via `MAX_MONEY` ceiling change if chain contains transactions relying on >21M-per-check acceptance
- historical wallet files: **NO direct format impact observed**
- database formats: **NO format impact observed**
- node registration behaviour: **YES** (duplicate-IP checks removed)
- transaction validity: **POSSIBLE** (for high-value MoneyRange boundary cases)
- serialized network messages: **NO format change**
- consensus state: **POSSIBLE** (money-range rule boundary)

**Revert risk classification: MEDIUM**

Reason: registration-policy effects are likely operational; however `MAX_MONEY` boundary is consensus/monetary-adjacent and was changed without accompanying historical-chain proof in PR #1.

---

## 8) Recommendation

**KEEP PR #1 BUT REWRITE/FIX IT**

Technical basis:
1. PR #1 mixes multiple concerns (monetary boundary + MN/SN admission policy + RPC/UI UX) in one unscoped change.
2. Original PR #1 duplicate-IP `CheckAndUpdate` lines required later corrective edits in revival (`fd810b6a00217f6d5e856963a6cc760e664e5fac`), indicating insufficient original hardening.
3. Preferred disposition for duplicate-IP logic: **retain concept, rewrite implementation** as identity-aware (`addr` conflict only when `vin` differs), peer-equivalent, and test-backed in both broadcast-validation and operator RPC/UI paths.
4. Current prechecks (`RPC/UI` and `CheckInputsAndAdd` guard style) rely on local in-memory address presence and can over-reject self/expected operator flows; this is the main rewrite target.
5. Preferred disposition for `MAX_MONEY` change: **do not keep by default**; keep only if explicit chain-evidence and consensus tests justify `42,000,000`, otherwise revert that part.

---

## 9) Documentation artifact

This document is the requested artifact:
- `docs/revival/HISTORICAL_PR1_AUDIT.md`

No production source files were edited for this audit.

---

## 10) Final report

- Crown 0.14.0.4 baseline SHA: `3050c1f970e6dc4713c41a88f80638c597af33e9`
- PR #1 merge SHA: `487053abf22c7bacdfad80fad1081f856db9b940`
- Files changed by PR #1:
  - `src/amount.h`
  - `src/masternode.cpp`
  - `src/masternodeman.cpp`
  - `src/masternodeman.h`
  - `src/qt/createnodedialog.cpp`
  - `src/rpcmasternode.cpp`
  - `src/rpcsystemnode.cpp`
  - `src/systemnode.cpp`
  - `src/systemnodeman.cpp`
  - `src/systemnodeman.h`

- Only pre-revival fork modification: **YES** (scoped to the PR #1-era pre-revival state `487053abf...` vs clean `v0.14.0.4` for production source; non-production install-script delta also exists)
- Consensus-sensitive: **POSSIBLE**
- MNPoS-sensitive: **POSSIBLE**
- Monetary-sensitive: **YES**
- Wallet-format-sensitive: **NO**
- P2P/wire-sensitive: **YES**
- Related to current discovered defects: **PARTIALLY**
- Revert risk: **MEDIUM**
- Recommendation: **FIX**
- Production source modified by this audit: **NO**
