#include <iostream>
#include <vector>
#include <string>
#include <numeric>
#include <algorithm>
#include <iomanip>
using namespace std;

// DES basic constants

const vector<int> IP = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

const vector<int> IP_INV = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};

const vector<int> E = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

const vector<vector<vector<int>>> S_BOX = {
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
    {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
    {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
    {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
    {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
    {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
    {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
};

const vector<int> P = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};

const vector<int> PC_1 = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51,
    43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};

const vector<int> PC_2 = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

const vector<int> shifts_table = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Bit Conversion and Operation

vector<int> string_to_bits(const string& text){
    vector<int> bits;
    for(char c : text){
        for(int i = 7; i >= 0; --i) bits.push_back((c >> i) & 1);
    }
    return bits;
}

string bits_to_string(const vector<int>& bits){
    string text = "";
    for(size_t i = 0; i < bits.size(); i += 8){
        int byte = 0;
        for(int j = 0; j < 8; ++j) byte = (byte << 1) | bits[i + j];
        text += static_cast<char>(byte);
    }
    return text;
}

string bits_to_hex(const vector<int>& bits){
    stringstream ss;
    ss << hex << setfill('0');
    for(size_t i = 0; i < bits.size(); i += 4){
        int nibble = 0;
        for(int j = 0; j < 4; ++j) nibble = (nibble << 1) | bits[i + j];
        ss << setw(1) << nibble;
    }
    return ss.str();
}

vector<int> int_to_bits(int n, int len){
    vector<int> bits(len);
    for(int i = len - 1; i >= 0; --i){
        bits[i] = n & 1;
        n >>= 1;
    }
    return bits;
}

vector<int> xor_bits(const vector<int>& a, const vector<int>& b){
    vector<int> result;
    for(size_t i = 0; i < a.size(); ++i) result.push_back(a[i] ^ b[i]);
    return result;
}

// DES core implementation

vector<int> permute(const vector<int>& block, const vector<int>& table){
    vector<int> result;
    for(int i : table) result.push_back(block[i - 1]);
    return result;
}

vector<vector<int>> generate_round_keys(const vector<int>& key_bits){
    vector<int> key = permute(key_bits, PC_1);
    vector<int> C(key.begin(), key.begin() + 28);
    vector<int> D(key.begin() + 28, key.end());

    vector<vector<int>> round_keys;
    for(int shift : shifts_table){
        rotate(C.begin(), C.begin() + shift, C.end());
        rotate(D.begin(), D.begin() + shift, D.end());

        vector<int> combined_key = C;
        combined_key.insert(combined_key.end(), D.begin(), D.end());
        round_keys.push_back(permute(combined_key, PC_2));
    }
    return round_keys;
}

// Feistel function in one round

vector<int> feistel_function(const vector<int>& right, const vector<int>& round_key){
    vector<int> right_expanded = permute(right, E);
    vector<int> xored = xor_bits(right_expanded, round_key);
    
    vector<int> sbox_output;
    for(int i = 0; i < 8; ++i){
        vector<int> chunk(xored.begin() + i*6, xored.begin() + (i+1)*6);
        int row = chunk[0] * 2 + chunk[5];
        int col = chunk[1] * 8 + chunk[2] * 4 + chunk[3] * 2 + chunk[4];
        int val = S_BOX[i][row][col];
        vector<int> val_bits = int_to_bits(val, 4);
        sbox_output.insert(sbox_output.end(), val_bits.begin(), val_bits.end());
    }
    return permute(sbox_output, P);
}

// Main function to process one 64bit block

vector<int> des_process_block(const vector<int>& block_bits, const vector<vector<int>>& round_keys){
    vector<int> permuted_block = permute(block_bits, IP);
    vector<int> left(permuted_block.begin(), permuted_block.begin() + 32);
    vector<int> right(permuted_block.begin() + 32, permuted_block.end());

    for(int i = 0; i < 16; ++i){
        vector<int> new_right = xor_bits(left, feistel_function(right, round_keys[i]));
        left = right;
        right = new_right;
    }

    vector<int> final_block_data = right;
    final_block_data.insert(final_block_data.end(), left.begin(), left.end());
    
    return permute(final_block_data, IP_INV);
}

// Padding and CBC Operation

string add_padding(const string& data){
    int block_size = 8;
    int padding_len = block_size - (data.length() % block_size);
    if(padding_len == 0) padding_len = block_size;
    string padded_data = data;
    for(int i = 0; i < padding_len; ++i) padded_data += static_cast<char>(padding_len);
    return padded_data;
}

string remove_padding(const string& data){
    if(data.empty()) return "";
    int padding_len = static_cast<int>(data.back());
    if(padding_len < 1 || padding_len > 8) return data;
    return data.substr(0, data.length() - padding_len);
}

string des_encrypt_cbc(const string& plaintext, const string& key, const string& iv){
    string padded_plaintext = add_padding(plaintext);
    vector<int> key_bits = string_to_bits(key);
    vector<int> iv_bits = string_to_bits(iv);

    auto round_keys = generate_round_keys(key_bits);

    string ciphertext = "";
    vector<int> previous_cipher_block = iv_bits;

    for(size_t i = 0; i < padded_plaintext.length(); i += 8){
        string block_str = padded_plaintext.substr(i, 8);
        vector<int> block_bits = string_to_bits(block_str);
        
        vector<int> block_to_encrypt = xor_bits(block_bits, previous_cipher_block);
        vector<int> encrypted_block = des_process_block(block_to_encrypt, round_keys);
        
        ciphertext += bits_to_string(encrypted_block);
        previous_cipher_block = encrypted_block;
    }
    return ciphertext;
}

string des_decrypt_cbc(const string& ciphertext, const string& key, const string& iv){
    vector<int> key_bits = string_to_bits(key);
    vector<int> iv_bits = string_to_bits(iv);

    auto round_keys = generate_round_keys(key_bits);
    reverse(round_keys.begin(), round_keys.end());

    string plaintext = "";
    vector<int> previous_cipher_block = iv_bits;

    for(size_t i = 0; i < ciphertext.length(); i += 8){
        string block_str = ciphertext.substr(i, 8);
        vector<int> block_bits = string_to_bits(block_str);
        
        vector<int> decrypted_block_intermediate = des_process_block(block_bits, round_keys);
        vector<int> plaintext_block = xor_bits(decrypted_block_intermediate, previous_cipher_block);
        
        plaintext += bits_to_string(plaintext_block);
        previous_cipher_block = block_bits;
    }
    return remove_padding(plaintext);
}

// Main function

void print_hex(const string& label, const string& data){
    cout << label << ": ";
    for(unsigned char c : data) cout << hex << setw(2) << setfill('0') << static_cast<int>(c);
    cout << dec << endl;
}


int main(){
    string key, iv;

    system("CLS");
    cout << "--- DES Enkripsi/Dekripsi ---\n";
    
    while(key.length() != 8){
        cout << "Masukkan Kunci (8 karakter): ";
        getline(cin, key);
        if(key.length() != 8) cout << "Error: Panjang kunci tidak valid." << endl;
    }
    
    while(iv.length() != 8){
        cout << "Masukkan IV (8 karakter): ";
        getline(cin, iv);
        if(iv.length() != 8) cout << "Error: Panjang IV tidak valid." << endl;
    }
    
    int choice;
    system("CLS");
    cout << "--- DES Enkripsi/Dekripsi ---\n";
    cout << "Kunci: " << key;
    cout << "\nIV: " << iv;
    cout << "\n\nPilih operasi:" << endl;
    cout << "1. Enkripsi" << endl;
    cout << "2. Dekripsi" << endl;
    cout << "Pilihan(1/2): ";
    cin >> choice;
    cin.ignore();

    if(choice == 1){
        string plaintext;
        system("CLS");
        cout << "--- Enkripsi ---\n";
        cout << "Masukkan Plaintext: ";
        getline(cin, plaintext);

        string ciphertext = des_encrypt_cbc(plaintext, key, iv);
        
        system("CLS");
        cout << "--- Hasil Enkripsi ---\n";
        cout << "Kunci: " << key << endl;
        cout << "IV: " << iv << endl;
        cout << "Plaintext Original : " << plaintext << endl;
        print_hex("Ciphertext (Hex) ", ciphertext);
        
    }else if(choice == 2){
        string hex_ciphertext_str;
        system("CLS");
        cout << "--- Dekripsi ---\n";
        cout << "Masukkan Ciphertext (dalam format Hex): ";
        getline(cin, hex_ciphertext_str);

        string ciphertext = "";
        try{
            for(size_t i = 0; i < hex_ciphertext_str.length(); i += 2){
                string byteString = hex_ciphertext_str.substr(i, 2);
                char byte = static_cast<char>(stoi(byteString, nullptr, 16));
                ciphertext += byte;
            }
        
            string decrypted_text = des_decrypt_cbc(ciphertext, key, iv);

            system("CLS");
            cout << "--- Hasil Dekripsi ---" << endl;
            cout << "Kunci: " << key << endl;
            cout << "IV: " << iv << endl;
            print_hex("Ciphertext (Hex) ", ciphertext);
            cout << "Plaintext Didekripsi : " << decrypted_text << endl;

        }catch(const exception& e){
            cerr << "Error: Format Hex tidak valid. Pastikan panjangnya genap dan hanya berisi 0-9, a-f." << endl;
        }
    }else cout << "Pilihan tidak valid." << endl;
    return 0;
}
