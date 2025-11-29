#include "SecureVault.h"
#include <iostream>
#include <limits> 

void clearInput() {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void printMainMenu(std::string loggedInUser) {
    std::cout << "\n=== SECUREVAULT (HYBRID ENGINE) ===\n";
    if (loggedInUser.empty()) {
        std::cout << "STATUS: Not Logged In\n";
        std::cout << "1. Register User\n";
        std::cout << "2. Login\n";
        std::cout << "-----------------------------------\n";
        std::cout << "9. Admin Export (CSV)\n";
        std::cout << "10. Backup Encrypted Database (.db)\n";
        std::cout << "11. Restore/Recover Database\n";
        std::cout << "-----------------------------------\n";
        std::cout << "7. Exit\n";
    } else {
        std::cout << "STATUS: Logged in as " << loggedInUser << "\n";
        std::cout << "3. Add New Credential\n";
        std::cout << "4. View Credentials\n";
        std::cout << "5. Update Master Password\n";
        std::cout << "6. View Password History\n";
        std::cout << "8. Logout\n";
        std::cout << "-----------------------------------\n";
        std::cout << "12. Edit Credential\n";
        std::cout << "13. View Decrypted Password\n";
        std::cout << "14. Set Secondary PIN\n";
        std::cout << "15. Remove Secondary PIN\n";
    }
    std::cout << "Select: ";
}

int main() {
    SecureVault vault("vault.db", "vault.idx");
    int choice = 0;
    std::string activeUser = "";
    std::string username, password, service, sUsername, sPassword, newPass, pin;
    std::string backupDB, backupIdx;

    while (true) {
        printMainMenu(activeUser);
        if (!(std::cin >> choice)) {
            std::cout << "Invalid input.\n";
            clearInput(); continue;
        }
        clearInput(); 

        switch (choice) {
            case 1: 
                std::cout << "New Username: "; std::getline(std::cin, username);
                std::cout << "New Password: "; std::getline(std::cin, password);
                if (vault.registerUser(username, password)) { }
                break;
            case 2: 
                std::cout << "Username: "; std::getline(std::cin, username);
                std::cout << "Password: "; std::getline(std::cin, password);
                if (vault.loginUser(username, password)) activeUser = username;
                break;
            case 3: 
                if (activeUser.empty()) break;
                std::cout << "Service Name: "; std::getline(std::cin, service);
                std::cout << "Service Username: "; std::getline(std::cin, sUsername);
                std::cout << "Service Password: "; std::getline(std::cin, sPassword);
                // UPDATED: Ask for Master Password to encrypt data
                std::cout << "Confirm Master Password (for encryption): "; std::getline(std::cin, password);
                vault.addCredential(activeUser, service, sUsername, sPassword, password);
                break;
            case 4: 
                 if (activeUser.empty()) break;
                 vault.viewCredentials(activeUser);
                 break;
            case 5:
                 if (activeUser.empty()) break;
                 std::cout << "Old Pass: "; std::getline(std::cin, password);
                 std::cout << "New Pass: "; std::getline(std::cin, newPass);
                 vault.updatePassword(activeUser, password, newPass);
                 break;
            case 6:
                 if (activeUser.empty()) break;
                 vault.printHistory(activeUser);
                 break;
            case 7: return 0;
            case 8: vault.logoutUser(activeUser); activeUser = ""; break;
            case 9:
                 std::cout << "Admin Pass: "; std::getline(std::cin, password);
                 std::cout << "Confirm: "; std::getline(std::cin, newPass);
                 vault.exportDatabaseToCSV(password, newPass);
                 break;
            case 10: vault.exportEncryptedDatabase(); break;
            case 11:
                 std::cout << "Backup DB File: "; std::getline(std::cin, backupDB);
                 std::cout << "Backup Idx File: "; std::getline(std::cin, backupIdx);
                 std::cout << "Confirm (YES): "; std::getline(std::cin, password);
                 if (password == "YES") {
                     vault.importEncryptedDatabase(backupDB, backupIdx);
                     activeUser = "";
                 }
                 break;
            case 12: // Edit Credential
                 if (activeUser.empty()) break;
                 std::cout << "Service to Edit: "; std::getline(std::cin, service);
                 std::cout << "New Username: "; std::getline(std::cin, sUsername);
                 std::cout << "New Password: "; std::getline(std::cin, sPassword);
                 // UPDATED: Ask for Master Password to encrypt data
                 std::cout << "Confirm Master Password (for encryption): "; std::getline(std::cin, password);
                 vault.editCredential(activeUser, service, sUsername, sPassword, password);
                 break;
            case 13: // View Decrypted
                 if (activeUser.empty()) break;
                 std::cout << "Service Name: "; std::getline(std::cin, service);
                 std::cout << "Enter PIN (or Master Password): "; std::getline(std::cin, password);
                 vault.viewDecryptedCredential(activeUser, service, password);
                 break;
            case 14: // Set PIN
                 if (activeUser.empty()) break;
                 std::cout << "Enter New PIN: "; std::getline(std::cin, pin);
                 std::cout << "Confirm with Master Password: "; std::getline(std::cin, password);
                 vault.setSecondaryPin(activeUser, pin, password);
                 break;
            case 15: // Remove PIN
                 if (activeUser.empty()) break;
                 std::cout << "Confirm with Master Password: "; std::getline(std::cin, password);
                 vault.removeSecondaryPin(activeUser, password);
                 break;
            default: std::cout << "Unknown option.\n";
        }
    }
}
