#include "BTree.h"

using namespace std;

BTree::BTree(std::string indexFile) : filename(indexFile) {
    fstream file(filename, ios::in | ios::out | ios::binary);
    if (!file.is_open()) {
        file.open(filename, ios::out | ios::binary);
        file.close();
        
        // Initialize Root on Heap
        BTreeNode* root = new BTreeNode();
        fstream initFile(filename, ios::out | ios::binary);
        initFile.write(reinterpret_cast<char*>(root), sizeof(BTreeNode));
        initFile.close();
        delete root;
    }
    rootOffset = 0; // Root is always at 0
}

BTree::~BTree() {
}

// --- Heap-Based Disk I/O ---

void BTree::writeNode(long offset, BTreeNode* node) {
    fstream file(filename, ios::in | ios::out | ios::binary);
    file.seekp(offset, ios::beg);
    file.write(reinterpret_cast<char*>(node), sizeof(BTreeNode));
    file.close();
}

void BTree::readNode(long offset, BTreeNode* node) {
    fstream file(filename, ios::in | ios::binary);
    file.seekg(offset, ios::beg);
    file.read(reinterpret_cast<char*>(node), sizeof(BTreeNode));
    file.close();
}

long BTree::getFreeOffset() {
    fstream file(filename, ios::in | ios::out | ios::binary);
    file.seekp(0, ios::end);
    long pos = file.tellp();
    file.close();
    return pos;
}

// --- Search ---

long BTree::search(const std::string& key) {
    long currentOffset = rootOffset;
    char k[KEY_SIZE];
    strncpy(k, key.c_str(), KEY_SIZE);

    while (true) {
        BTreeNode* current = new BTreeNode(); // HEAP ALLOCATION
        readNode(currentOffset, current);

        int i = 0;
        while (i < current->numKeys && strncmp(k, current->keys[i], KEY_SIZE) > 0) {
            i++;
        }

        if (current->isLeaf) {
            long result = -1;
            if (i < current->numKeys && strncmp(k, current->keys[i], KEY_SIZE) == 0) {
                result = current->children[i];
            }
            delete current; // CLEANUP
            return result;
        } else {
             if (i < current->numKeys && strncmp(k, current->keys[i], KEY_SIZE) == 0) {
                 i++; 
             }
            long nextOffset = current->children[i];
            delete current; // CLEANUP
            currentOffset = nextOffset;
        }
    }
}

// --- Insert ---

void BTree::insert(const std::string& key, long dataOffset) {
    BTreeNode* root = new BTreeNode();
    readNode(rootOffset, root);

    if (root->numKeys == 2 * T - 1) {
        // Root is full, split it
        BTreeNode* newRoot = new BTreeNode();
        newRoot->isLeaf = false;
        newRoot->children[0] = rootOffset;
        
        long oldRootMovedPos = getFreeOffset();
        writeNode(oldRootMovedPos, root);
        
        // Reset physical root at 0
        newRoot->children[0] = oldRootMovedPos;
        writeNode(rootOffset, newRoot);
        
        splitChild(rootOffset, 0, oldRootMovedPos);
        insertNonFull(rootOffset, key, dataOffset);
        
        delete newRoot;
    } else {
        insertNonFull(rootOffset, key, dataOffset);
    }
    delete root;
}

void BTree::splitChild(long parentOffset, int index, long childOffset) {
    BTreeNode* parent = new BTreeNode();
    BTreeNode* child = new BTreeNode();
    BTreeNode* newSibling = new BTreeNode();

    readNode(parentOffset, parent);
    readNode(childOffset, child);

    newSibling->isLeaf = child->isLeaf;
    newSibling->numKeys = T - 1;
    newSibling->nextLeaf = child->nextLeaf;

    for (int j = 0; j < T - 1; j++) {
        strncpy(newSibling->keys[j], child->keys[j + T], KEY_SIZE);
    }

    if (!child->isLeaf) {
        for (int j = 0; j < T; j++) {
            newSibling->children[j] = child->children[j + T];
        }
    } else {
        for (int j = 0; j < T - 1; j++) {
            newSibling->children[j] = child->children[j + T];
        }
    }

    child->numKeys = T - 1;
    if (child->isLeaf) child->nextLeaf = getFreeOffset();

    for (int j = parent->numKeys; j >= index + 1; j--) {
        parent->children[j + 1] = parent->children[j];
    }
    
    long siblingOffset = getFreeOffset();
    parent->children[index + 1] = siblingOffset;

    for (int j = parent->numKeys - 1; j >= index; j--) {
        strncpy(parent->keys[j + 1], parent->keys[j], KEY_SIZE);
    }

    strncpy(parent->keys[index], newSibling->keys[0], KEY_SIZE);
    parent->numKeys++;

    writeNode(childOffset, child);
    writeNode(siblingOffset, newSibling);
    writeNode(parentOffset, parent);

    delete parent; delete child; delete newSibling;
}

void BTree::insertNonFull(long nodeOffset, const std::string& key, long dataOffset) {
    BTreeNode* node = new BTreeNode();
    readNode(nodeOffset, node);
    
    char k[KEY_SIZE];
    strncpy(k, key.c_str(), KEY_SIZE);

    int i = node->numKeys - 1;

    if (node->isLeaf) {
        while (i >= 0 && strncmp(node->keys[i], k, KEY_SIZE) > 0) {
            strncpy(node->keys[i + 1], node->keys[i], KEY_SIZE);
            node->children[i + 1] = node->children[i];
            i--;
        }
        
        if (i >= 0 && strncmp(node->keys[i], k, KEY_SIZE) == 0) {
            node->children[i] = dataOffset; // Update
        } else {
            strncpy(node->keys[i + 1], k, KEY_SIZE);
            node->children[i + 1] = dataOffset;
            node->numKeys++;
        }
        writeNode(nodeOffset, node);
    } else {
        while (i >= 0 && strncmp(node->keys[i], k, KEY_SIZE) > 0) {
            i--;
        }
        i++;
        long childOffset = node->children[i];
        
        BTreeNode* child = new BTreeNode();
        readNode(childOffset, child);
        if (child->numKeys == 2 * T - 1) {
            splitChild(nodeOffset, i, childOffset);
            readNode(nodeOffset, node); 
            if (strncmp(node->keys[i], k, KEY_SIZE) < 0) {
                i++;
            }
        }
        delete child;
        insertNonFull(node->children[i], key, dataOffset);
    }
    delete node;
}
