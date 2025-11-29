#pragma once
#include <fstream>
#include <iostream>
#include <cstring>
#include <string>

// --- Configuration ---
const int T = 3; // Minimum degree (Order)
const int KEY_SIZE = 32; 

// --- Disk Node Structure ---
struct BTreeNode {
    bool isLeaf;
    int numKeys;
    char keys[2 * T - 1][KEY_SIZE]; 
    long children[2 * T];           // Offsets to children or data
    long nextLeaf;                  // Linked list of leaves

    BTreeNode() {
        isLeaf = true;
        numKeys = 0;
        nextLeaf = -1;
        for (int i = 0; i < 2 * T; i++) children[i] = -1;
        for (int i = 0; i < 2 * T - 1; i++) std::memset(keys[i], 0, KEY_SIZE);
    }
};

class BTree {
public:
    BTree(std::string indexFile);
    ~BTree();

    long search(const std::string& key); 
    void insert(const std::string& key, long dataOffset);

private:
    std::string filename;
    long rootOffset;

    // Helpers
    void writeNode(long offset, BTreeNode* node);
    void readNode(long offset, BTreeNode* node); // Allocates to heap
    long getFreeOffset(); 

    // Logic
    void insertNonFull(long nodeOffset, const std::string& key, long dataOffset);
    void splitChild(long parentOffset, int index, long childOffset);
};
