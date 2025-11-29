#include "SecureVault.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector> 
#include <cstdio>
#include <random> // Added for better randomness

using namespace std;

// --- CONFIGURATION ---
const string DB_ENCRYPTION_KEY = "S3cur3V4ult#K3y!v1"; 

bool copyFile(const string& src, const string& dst) {
    ifstream in(src, ios::binary);
    ofstream out(dst, ios::binary);
    if (!in || !out) return false;
    out << in.rdbuf();
    return true;
}

SecureVault::SecureVault(string dbFile, string idxFile) : dbFilename(dbFile) {
    index = new BTree(idxFile);
    cache = new HashNode*[TABLE_SIZE];
    for(int i=0; i<TABLE_SIZE; ++i) cache[i] = nullptr;
}

SecureVault::~SecureVault() {
    for(int i=0; i<TABLE_SIZE; ++i) {
        HashNode* curr = cache[i];
        while(curr) {
            HashNode* temp = curr;
            curr = curr->next;
            delete temp->authData; 
            delete temp;
        }
    }
    delete[] cache;
    delete index;
}

int SecureVault::hash(const string& key) {
    unsigned long hash = 5381;
    for (char c : key) hash = ((hash << 5) + hash) + c; 
    return hash % TABLE_SIZE;
}

// --- HELPERS ---

void applyCipher(vector<char>& data) {
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= DB_ENCRYPTION_KEY[i % DB_ENCRYPTION_KEY.length()];
    }
}

string SecureVault::xorEncrypt(string data, string key) {
    if (key.empty()) return data;
    string result = data;
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] ^= key[i % key.length()];
    }
    return result;
}

int SecureVault::checkPasswordStrength(const string& password) {
    int score = 0;
    if (password.length() >= 8) score++;
    if (password.length() >= 12) score++; 
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSymbol = false;
    for (char c : password) {
        if (isupper(c)) hasUpper = true;
        else if (islower(c)) hasLower = true;
        else if (isdigit(c)) hasDigit = true;
        else hasSymbol = true; 
    }
    if (hasUpper) score++; if (hasLower) score++; if (hasDigit) score++; if (hasSymbol) score++;
    return score;
}

// --- CORE LOGIC ---

bool SecureVault::registerUser(const string& username, const string& password) {
    if (checkPasswordStrength(password) < 4) {
        cout << "[!] Password too weak (Min Score 4/5).\n";
        return false;
    }
    if (index->search(username) != -1) {
        cout << "[!] User already exists.\n";
        return false;
    }

    UserAuth* u = new UserAuth(); 
    u->username = username;
    u->salt = generateSalt();
    u->saltedHash = hashPassword(password, u->salt);
    u->lastActive = time(0);
    u->hasSecondaryPin = false;
    u->secondaryPinHash = "";
    u->encryptedPin = "";

    long offset = saveUserBlob(u); 
    index->insert(username, offset); 
    addToCache(u); 
    
    cout << "[+] User registered.\n";
    return true;
}

bool SecureVault::loginUser(const string& username, const string& password) {
    evictOldUsers(); 
    HashNode* node = findInCache(username);
    UserAuth* user = nullptr;

    if (node) {
        user = node->authData;
        user->lastActive = time(0); 
    } else {
        long offset = index->search(username);
        if (offset == -1) { cout << "[!] User not found.\n"; return false; }
        user = loadUserBlob(offset);
        if (!user) { cout << "[!] Critical Error: Failed to load.\n"; return false; }
        addToCache(user);
    }

    if (user->lockoutEnd > time(0)) {
        cout << "[!!!] ACCOUNT LOCKED.\n";
        return false;
    }

    if (hashPassword(password, user->salt) == user->saltedHash) {
        cout << "[+] Login Successful.\n";
        user->failedAttempts = 0; 
        return true;
    } else {
        user->failedAttempts++;
        if (user->failedAttempts >= 3) user->lockoutEnd = time(0) + 30; 
        cout << "[!] Invalid Password.\n";
        return false;
    }
}

void SecureVault::logoutUser(const string& username) {
    cout << "[+] User logged out locally.\n";
}

// --- NEW FEATURES: EDIT / PIN / DECRYPT ---

bool SecureVault::setSecondaryPin(const string& username, const string& pin, const string& masterPass) {
    if (!loginUser(username, masterPass)) return false; 

    HashNode* node = findInCache(username);
    UserAuth* u = node->authData;

    string salt = generateSalt();
    u->secondaryPinHash = hashPassword(pin, salt); 
    u->encryptedPin = xorEncrypt(pin, masterPass);
    u->hasSecondaryPin = true;

    cout << "[*] Migrating credentials to encrypted storage...\n";
    CredentialNode* curr = u->credentialHead;
    int count = 0;
    while(curr) {
        curr->encPass = xorEncrypt(curr->encPass, pin);
        curr = curr->next;
        count++;
    }

    long newOffset = saveUserBlob(u);
    index->insert(username, newOffset);
    cout << "[+] Secondary PIN set. " << count << " credentials encrypted.\n";
    return true;
}

bool SecureVault::removeSecondaryPin(const string& username, const string& masterPass) {
    if (!loginUser(username, masterPass)) return false;

    HashNode* node = findInCache(username);
    UserAuth* u = node->authData;

    if (u->hasSecondaryPin) {
        string recoveredPin = xorEncrypt(u->encryptedPin, masterPass);
        
        cout << "[*] Decrypting credentials...\n";
        CredentialNode* curr = u->credentialHead;
        while(curr) {
            curr->encPass = xorEncrypt(curr->encPass, recoveredPin);
            curr = curr->next;
        }
        
        u->hasSecondaryPin = false;
        u->secondaryPinHash = "";
        u->encryptedPin = "";
        
        long newOffset = saveUserBlob(u);
        index->insert(username, newOffset);
        cout << "[+] Secondary PIN removed. Credentials stored as standard blob.\n";
        return true;
    } else {
        cout << "[!] No Secondary PIN active.\n";
        return false;
    }
}

bool SecureVault::addCredential(const string& username, const string& srv, const string& usr, const string& pwd, const string& masterPass) {
    HashNode* node = findInCache(username);
    if (!node) { cout << "[!] Please login first.\n"; return false; }
    
    UserAuth* u = node->authData;
    u->lastActive = time(0);

    if (hashPassword(masterPass, u->salt) != u->saltedHash) {
        cout << "[!] Invalid Master Password. Cannot verify encryption key.\n";
        return false;
    }

    CredentialNode* cred = new CredentialNode();
    cred->service = srv;
    cred->username = usr;
    cred->iv = generateSalt().substr(0, 8); 

    if (u->hasSecondaryPin) {
        string pin = xorEncrypt(u->encryptedPin, masterPass);
        cred->encPass = xorEncrypt(pwd, pin);
        cout << "[+] Credential encrypted with Secondary PIN.\n";
    } else {
        cred->encPass = pwd; 
        cout << "[+] Credential stored (Standard).\n";
    }
    
    cred->next = u->credentialHead;
    u->credentialHead = cred;

    long newOffset = saveUserBlob(u);
    index->insert(username, newOffset);
    return true;
}

bool SecureVault::editCredential(const string& username, const string& service, const string& newUsr, const string& newPwd, const string& masterPass) {
    HashNode* node = findInCache(username);
    if (!node) return false;

    if (hashPassword(masterPass, node->authData->salt) != node->authData->saltedHash) {
         cout << "[!] Invalid Master Password.\n";
         return false;
    }
    
    UserAuth* u = node->authData;
    CredentialNode* curr = u->credentialHead;
    while(curr) {
        if (curr->service == service) {
            curr->username = newUsr;
            
            if (u->hasSecondaryPin) {
                 string pin = xorEncrypt(u->encryptedPin, masterPass);
                 curr->encPass = xorEncrypt(newPwd, pin);
            } else {
                 curr->encPass = newPwd;
            }
            
            long newOffset = saveUserBlob(u);
            index->insert(username, newOffset);
            cout << "[+] Credential '" << service << "' updated.\n";
            return true;
        }
        curr = curr->next;
    }
    cout << "[!] Service not found.\n";
    return false;
}

void SecureVault::viewDecryptedCredential(const string& username, const string& service, const string& authInput) {
    HashNode* node = findInCache(username);
    if (!node) return;
    
    UserAuth* u = node->authData;
    
    CredentialNode* target = nullptr;
    CredentialNode* curr = u->credentialHead;
    while(curr) {
        if (curr->service == service) { target = curr; break; }
        curr = curr->next;
    }
    
    if (!target) { cout << "[!] Service not found.\n"; return; }
    
    if (!u->hasSecondaryPin) {
        cout << "Password: " << target->encPass << endl;
        return;
    }

    if (hashPassword(authInput, u->salt) == u->saltedHash) {
        cout << "[*] Master Override Accepted.\n";
        
        string recoveredPin = xorEncrypt(u->encryptedPin, authInput);
        string plain = xorEncrypt(target->encPass, recoveredPin);
        
        cout << "Password: " << plain << endl;
        return;
    }
    
    cout << "[!] Decryption failed. Please use Master Password.\n";
}

void SecureVault::viewCredentials(const string& username) {
    HashNode* node = findInCache(username);
    if (!node) { cout << "[!] Please login first.\n"; return; }
    
    UserAuth* u = node->authData;
    u->lastActive = time(0);

    cout << "\n--- Credentials for " << username << " ---\n";
    if (u->hasSecondaryPin) cout << "[LOCKED] Secondary PIN Active. Passwords hidden.\n";
    
    CredentialNode* curr = u->credentialHead;
    while(curr) {
        string displayPass = (u->hasSecondaryPin) ? "*****" : curr->encPass;
        cout << "Service: " << curr->service << " | User: " << curr->username << " | Pass: " << displayPass << endl;
        curr = curr->next;
    }
    cout << "--------------------------\n";
}


bool SecureVault::updatePassword(const string& username, const string& oldPass, const string& newPass) {
    if (checkPasswordStrength(newPass) < 4) { cout << "[!] Weak Password.\n"; return false; }
    if (!loginUser(username, oldPass)) return false;
    
    HashNode* node = findInCache(username);
    UserAuth* u = node->authData;

    HistoryNode* hCheck = u->historyHead;
    while(hCheck) {
        string checkHash = hashPassword(newPass, hCheck->salt);
        if (checkHash == hCheck->oldSaltedHash) { cout << "[!] Reuse detected.\n"; return false; }
        hCheck = hCheck->next;
    }

    HistoryNode* h = new HistoryNode();
    h->oldSaltedHash = u->saltedHash; h->salt = u->salt; h->timestamp = getCurrentTime();
    h->next = u->historyHead; u->historyHead = h;

    u->salt = generateSalt();
    u->saltedHash = hashPassword(newPass, u->salt);

    if (u->hasSecondaryPin) {
        string pin = xorEncrypt(u->encryptedPin, oldPass);
        u->encryptedPin = xorEncrypt(pin, newPass);
    }

    long newOffset = saveUserBlob(u);
    index->insert(username, newOffset);
    cout << "[+] Password Updated.\n";
    return true;
}

void SecureVault::printHistory(const string& username) {
    HashNode* node = findInCache(username);
    if (!node) { cout << "[!] Please login first.\n"; return; }
    
    HistoryNode* h = node->authData->historyHead;
    cout << "\n--- History ---\n";
    while(h) {
        cout << h->timestamp << ": " << h->oldSaltedHash.substr(0, 8) << "...\n";
        h = h->next;
    }
}

// --- ADMIN & STORAGE ---

bool SecureVault::exportDatabaseToCSV(string adminPass1, string adminPass2) {
    if (adminPass1 != adminPass2) return false;
    long offset = index->search("admin");
    if (offset == -1) return false;
    UserAuth* admin = loadUserBlob(offset);
    if (!admin) return false;
    if (hashPassword(adminPass1, admin->salt) != admin->saltedHash) { delete admin; return false; }
    delete admin;

    ofstream csvFile("vault_export.csv");
    csvFile << "Owner,MasterHash,Service,Username,Password\n";
    fstream db(dbFilename, ios::in | ios::binary);
    db.seekg(0, ios::beg);

    while (db.peek() != EOF) {
        long currentPos = db.tellg();
        size_t blobSize;
        if (!db.read((char*)&blobSize, sizeof(size_t))) break;
        db.seekg(blobSize, ios::cur);
        UserAuth* u = loadUserBlob(currentPos);
        if (u) {
            if (u->credentialHead == nullptr) {
                csvFile << u->username << "," << u->saltedHash << ",(No Credentials),,\n";
            } else {
                CredentialNode* c = u->credentialHead;
                while(c) {
                    csvFile << u->username << "," << u->saltedHash << "," << c->service << "," << c->username << "," << c->encPass << "\n";
                    c = c->next;
                }
            }
            delete u;
        }
    }
    csvFile.close();
    cout << "[+] Export complete.\n";
    return true;
}

bool SecureVault::exportEncryptedDatabase() {
    return copyFile(dbFilename, "vault_backup.db") && copyFile("vault.idx", "vault_backup.idx");
}

bool SecureVault::importEncryptedDatabase(string backupDB, string backupIdx) {
    ifstream check1(backupDB); ifstream check2(backupIdx);
    if (!check1 || !check2) { 
        cout << "[!] Error: Backup files not found.\n"; 
        return false; 
    }
    check1.close(); check2.close();

    cout << "[*] Starting import with failsafe protection...\n";

    // 1. Create Restore Points
    string restoreDB = dbFilename + ".restore";
    string restoreIdx = "vault.idx.restore";
    
    bool hasCurrentDB = copyFile(dbFilename, restoreDB);
    bool hasCurrentIdx = copyFile("vault.idx", restoreIdx);

    // 2. Clear RAM Cache
    for(int i=0; i<TABLE_SIZE; ++i) {
        HashNode* curr = cache[i];
        while(curr) {
            HashNode* temp = curr;
            curr = curr->next;
            delete temp->authData;
            delete temp;
        }
        cache[i] = nullptr;
    }

    // 3. Close Index
    delete index;
    index = nullptr;

    // 4. Attempt Overwrite
    bool importSuccess = copyFile(backupDB, dbFilename) && copyFile(backupIdx, "vault.idx");

    // 5. Verification
    if (importSuccess) {
        try {
            index = new BTree("vault.idx");
            cout << "[+] Database imported successfully.\n";
            if (hasCurrentDB) remove(restoreDB.c_str());
            if (hasCurrentIdx) remove(restoreIdx.c_str());
            return true;
        } catch (...) {
            cout << "[!] Error: Imported database index seems corrupt. Rolling back...\n";
            importSuccess = false; 
        }
    }

    // 6. Rollback Logic
    if (!importSuccess) {
        cout << "[!] Critical: Import failed. Restoring original data...\n";
        if (index) { delete index; index = nullptr; }
        if (hasCurrentDB) copyFile(restoreDB, dbFilename);
        if (hasCurrentIdx) copyFile(restoreIdx, "vault.idx");
        index = new BTree("vault.idx"); 
        if (hasCurrentDB) remove(restoreDB.c_str());
        if (hasCurrentIdx) remove(restoreIdx.c_str());
        return false;
    }
    return true;
}

void SecureVault::evictOldUsers() {
    time_t now = time(0);
    double TIMEOUT = 300.0; 

    for(int i=0; i<TABLE_SIZE; ++i) {
        HashNode* prev = nullptr;
        HashNode* curr = cache[i];
        while(curr) {
            if (difftime(now, curr->authData->lastActive) > TIMEOUT) {
                HashNode* toDelete = curr;
                if (prev) prev->next = curr->next;
                else cache[i] = curr->next;
                
                curr = curr->next; // Advance to next before deleting
                
                delete toDelete->authData; 
                delete toDelete;
            } else {
                prev = curr;
                curr = curr->next;
            }
        }
    }
}

void SecureVault::addToCache(UserAuth* user) {
    int idx = hash(user->username);
    HashNode* n = new HashNode();
    n->authData = user;
    n->next = cache[idx];
    cache[idx] = n;
}

HashNode* SecureVault::findInCache(const std::string& username) {
    int idx = hash(username);
    HashNode* curr = cache[idx];
    while(curr) {
        if (curr->authData->username == username) return curr;
        curr = curr->next;
    }
    return nullptr;
}

void SecureVault::removeFromCache(const std::string& username) {
    int idx = hash(username);
    HashNode* curr = cache[idx];
    HashNode* prev = nullptr;
    while(curr) {
        if (curr->authData->username == username) {
            if (prev) prev->next = curr->next;
            else cache[idx] = curr->next;
            delete curr->authData;
            delete curr;
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

// --- STORAGE ---

long SecureVault::saveUserBlob(UserAuth* user) {
    vector<char> buffer;
    auto pushS = [&](string s) {
        size_t len = s.length();
        const char* p = (const char*)&len;
        buffer.insert(buffer.end(), p, p+sizeof(size_t));
        buffer.insert(buffer.end(), s.c_str(), s.c_str()+len);
    };
    auto pushI = [&](int val) {
        const char* p = (const char*)&val;
        buffer.insert(buffer.end(), p, p+sizeof(int));
    };

    pushS(user->username); pushS(user->saltedHash); pushS(user->salt);
    
    pushI(user->hasSecondaryPin ? 1 : 0);
    pushS(user->secondaryPinHash);
    pushS(user->encryptedPin);

    int hC = 0; HistoryNode* h = user->historyHead; while(h){hC++; h=h->next;}
    pushI(hC);
    h = user->historyHead;
    while(h) { pushS(h->oldSaltedHash); pushS(h->salt); pushS(h->timestamp); h=h->next; }

    int cC = 0; CredentialNode* c = user->credentialHead; while(c){cC++; c=c->next;}
    pushI(cC);
    c = user->credentialHead;
    while(c) { pushS(c->service); pushS(c->username); pushS(c->encPass); pushS(c->iv); c=c->next; }

    applyCipher(buffer);

    fstream file(dbFilename, ios::in | ios::out | ios::binary | ios::app);
    if (!file.is_open()) {
        file.open(dbFilename, ios::out | ios::binary);
        file.close();
        file.open(dbFilename, ios::in | ios::out | ios::binary | ios::app);
    }
    file.seekp(0, ios::end);
    long offset = file.tellp();
    size_t sz = buffer.size();
    file.write((char*)&sz, sizeof(size_t));
    file.write(buffer.data(), sz);
    file.close();
    return offset;
}

UserAuth* SecureVault::loadUserBlob(long offset) {
    fstream file(dbFilename, ios::in | ios::binary);
    file.seekg(offset, ios::beg);
    size_t sz;
    if(!file.read((char*)&sz, sizeof(size_t))) return nullptr;
    if (sz > 10*1024*1024) return nullptr; 

    vector<char> buffer(sz);
    file.read(buffer.data(), sz);
    file.close();
    applyCipher(buffer);

    UserAuth* u = new UserAuth();
    size_t pos = 0;
    auto readBytes = [&](void* d, size_t s) { memcpy(d, &buffer[pos], s); pos+=s; };
    auto readS = [&]() {
        size_t len; readBytes(&len, sizeof(size_t));
        string s(&buffer[pos], len); pos+=len; return s;
    };
    auto readI = [&]() { int v; readBytes(&v, sizeof(int)); return v; };

    try {
        u->username = readS(); u->saltedHash = readS(); u->salt = readS();
        
        u->hasSecondaryPin = (readI() == 1);
        u->secondaryPinHash = readS();
        u->encryptedPin = readS();

        int hC = readI();
        for(int i=0; i<hC; ++i) {
            HistoryNode* n = new HistoryNode();
            n->oldSaltedHash = readS(); n->salt = readS(); n->timestamp = readS();
            n->next = u->historyHead; u->historyHead = n;
        }
        int cC = readI();
        for(int i=0; i<cC; ++i) {
            CredentialNode* n = new CredentialNode();
            n->service = readS(); n->username = readS(); n->encPass = readS(); n->iv = readS();
            n->next = u->credentialHead; u->credentialHead = n;
        }
    } catch (...) { delete u; return nullptr; }
    return u;
}

// --- SECURE HASHING ALGORITHMS ---

string SecureVault::generateSalt() { 
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    string salt = "";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);
    
    // Generate 16 bytes of random salt
    for (int i = 0; i < 16; ++i) salt += alphanum[dis(gen)];
    return salt;
}

string SecureVault::hashPassword(const string& password, const string& salt) {
    // --- KEY STRETCHING IMPLEMENTATION ---
    // Simulates PBKDF2: 10,000 Iterations of Bit Mixing
    string currentHash = salt + password;
    for(int i=0; i < 10000; ++i) { 
        unsigned long hashVal = 5381;
        for (char c : currentHash) {
            hashVal = ((hashVal << 5) + hashVal) + c; // djb2 variant
            hashVal = hashVal ^ (hashVal >> 16);      // xor mix
        }
        stringstream ss; ss << hex << hashVal;
        
        // Re-salt periodically to prevent cycle reduction
        if (i % 100 == 0) currentHash = ss.str() + salt;
        else currentHash = ss.str();
    }
    return currentHash;
}

string SecureVault::getCurrentTime() { 
    time_t now = time(0);
    char* dt = ctime(&now);
    string s = dt ? dt : "Unknown";
    if (!s.empty() && s.back() == '\n') s.pop_back();
    return s;
}
