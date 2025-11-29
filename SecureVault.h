#pragma once
#include <string>
#include <fstream>
#include <ctime>
#include "BTree.h"

const int TABLE_SIZE = 100; 

// --- In-Memory Structures ---
struct HistoryNode {
    std::string oldSaltedHash, salt, timestamp; 
    HistoryNode* next;     
};

struct CredentialNode {
    std::string service, username, encPass, iv;
    CredentialNode* next;
};

// The Cache Object
struct UserAuth {
    std::string username;
    std::string saltedHash;
    std::string salt;
    time_t lastActive;

    // --- SECURITY FEATURES ---
    int failedAttempts = 0;
    time_t lockoutEnd = 0;
    
    // Secondary PIN Features
    bool hasSecondaryPin = false;
    std::string secondaryPinHash; // To verify PIN
    std::string encryptedPin;     // PIN encrypted with MasterPass (for recovery)

    HistoryNode* historyHead = nullptr;    
    CredentialNode* credentialHead = nullptr; 

    ~UserAuth() {
        while (historyHead) {
            HistoryNode* temp = historyHead;
            historyHead = historyHead->next;
            delete temp;
        }
        while (credentialHead) {
            CredentialNode* temp = credentialHead;
            credentialHead = credentialHead->next;
            delete temp;
        }
    }
};

// Hash Table Bucket
struct HashNode {
    UserAuth* authData; 
    HashNode* next; 
};

class SecureVault {
public:
    SecureVault(std::string dbFile, std::string idxFile);
    ~SecureVault();

    // User Management
    bool registerUser(const std::string& username, const std::string& password);
    bool loginUser(const std::string& username, const std::string& password);
    void logoutUser(const std::string& username);

    // Features
    // UPDATED: Now requires masterPass to encrypt the data if a PIN is active
    bool addCredential(const std::string& username, const std::string& srv, const std::string& usr, const std::string& pwd, const std::string& masterPass);
    void viewCredentials(const std::string& username);
    bool updatePassword(const std::string& username, const std::string& oldPass, const std::string& newPass);
    void printHistory(const std::string& username);
    
    // NEW FEATURES
    bool editCredential(const std::string& username, const std::string& service, const std::string& newUsr, const std::string& newPwd, const std::string& masterPass);
    void viewDecryptedCredential(const std::string& username, const std::string& service, const std::string& authInput);
    bool setSecondaryPin(const std::string& username, const std::string& pin, const std::string& masterPass);
    bool removeSecondaryPin(const std::string& username, const std::string& masterPass);

    // Admin Features
    bool exportDatabaseToCSV(std::string adminPass1, std::string adminPass2);
    bool exportEncryptedDatabase();
    bool importEncryptedDatabase(std::string backupDB, std::string backupIdx);

private:
    std::string dbFilename;
    BTree* index;      
    HashNode** cache; 

    // Helpers
    int hash(const std::string& key);
    std::string generateSalt();
    std::string hashPassword(const std::string& pass, const std::string& salt); 
    std::string getCurrentTime();
    std::string xorEncrypt(std::string data, std::string key); 
    
    // Security Helpers
    int checkPasswordStrength(const std::string& password);

    // Cache Management
    HashNode* findInCache(const std::string& username);
    void addToCache(UserAuth* user);
    void removeFromCache(const std::string& username);
    void evictOldUsers(); 

    // Blob Storage (Persistence)
    long saveUserBlob(UserAuth* user);
    UserAuth* loadUserBlob(long offset);
};
