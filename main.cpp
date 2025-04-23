#include<iostream>
#include<string>
#include<vector>
#include <cctype>
#include <sstream>
#include<iomanip>
using namespace std;

// State representation (4x4 matrix of bytes)
vector<vector<string>> initializeState(const string& input)
{
	vector<vector<string>> state(4, vector<string>(4));

	// Fill state column-wise (AES standard)
	for (int col = 0; col < 4; col++)
	{
		for (int row = 0; row < 4; row++)
		{
			int pos = col * 4 + row;
			state[row][col] = input.substr(pos * 2, 2); // Each byte is 2 hex chars
		}
	}

	return state;
}

// S-Box for substitution
unsigned char sbox[16][16] =
{
	{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
	{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
	{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
	{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
	{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
	{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
	{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
	{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
	{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
	{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
	{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
	{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
	{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
	{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
	{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
	{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};

// Round constants
unsigned char Rcon[11] =
{
	0x00, // just to align index (0 not used)
	0x01, 0x02, 0x04, 0x08,
	0x10, 0x20, 0x40, 0x80,
	0x1B, 0x36
};

// Convert a 4-byte word to individual bytes
vector<string> wordToBytes(const string& word)
{
	vector<string> bytes;
	for (int i = 0; i < 4; i++)
	{
		bytes.push_back(word.substr(i * 2, 2));
	}
	return bytes;
}

// Convert individual bytes back to a 4-byte word
string bytesToWord(const vector<string>& bytes)
{
	string word;
	for (const auto& byte : bytes)
	{
		word += byte;
	}
	return word;
}

// Apply S-Box substitution to a 4-byte word
void subWord(vector<string>& bytes)
{
	for (int i = 0; i < 4; i++)
	{
		int num = stoi(bytes[i], nullptr, 16);
		int row = (num & 0xF0) >> 4;
		int col = num & 0x0F;
		int sboxValue = sbox[row][col];

		char buffer[3];
		sprintf_s(buffer, sizeof(buffer), "%02X", sboxValue);
		bytes[i] = buffer;
	}
}

// Rotate and Substitute word for key expansion (RotWord + SubWord + Rcon)
void function_G(vector<string>& bytes, int round)
{
	// RotWord: circular byte left shift
	string temp = bytes[0];
	for (int i = 0; i < 3; i++)
	{
		bytes[i] = bytes[i + 1];
	}
	bytes[3] = temp;

	// SubWord: byte substitution using S-box
	subWord(bytes);

	// XOR with Rcon
	int firstByte = stoi(bytes[0], nullptr, 16);
	firstByte ^= Rcon[round];

	char buffer[3];
	sprintf_s(buffer, sizeof(buffer), "%02X", firstByte);
	bytes[0] = buffer;
}

// XOR two 4-byte words
string xorWords(const string& word1, const string& word2)
{
	string result;
	for (int i = 0; i < 8; i += 2)
	{
		int byte1 = stoi(word1.substr(i, 2), nullptr, 16);
		int byte2 = stoi(word2.substr(i, 2), nullptr, 16);
		int xorByte = byte1 ^ byte2;

		char buffer[3];
		sprintf_s(buffer, sizeof(buffer), "%02X", xorByte);
		result += buffer;
	}
	return result;
}

// Key expansion function
vector<string> expandKey(const string& key)
{
	vector<string> roundKeys;

	// The first round key is the original key
	roundKeys.push_back(key);

	// Generate 10 more round keys (AES-128)
	for (int i = 1; i <= 10; i++)
	{
		string lastKey = roundKeys.back();
		string newKey;

		// Split the last key into 4-byte words
		vector<string> words;
		for (int j = 0; j < 4; j++)
		{
			words.push_back(lastKey.substr(j * 8, 8));
		}

		// Process the first word of the new key
		vector<string> w3 = wordToBytes(words[3]);
		function_G(w3, i);
		string newWord0 = xorWords(words[0], bytesToWord(w3));
		newKey += newWord0;

		// Process the remaining words
		string newWord1 = xorWords(words[1], newWord0);
		newKey += newWord1;

		string newWord2 = xorWords(words[2], newWord1);
		newKey += newWord2;

		string newWord3 = xorWords(words[3], newWord2);
		newKey += newWord3;

		roundKeys.push_back(newKey);
	}

	return roundKeys;
}

// Validate hexadecimal input key
bool validateInputKey(const string& key)
{
	if (key.length() != 32)
	{
		cout << "Key must be 32 characters long (16 bytes)" << endl;
		return false;
	}
	for (char c : key)
	{
		if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
		{
			cout << "Key must contain only hexadecimal characters (0-9, A-F)" << endl;
			return false;
		}
	}
	return true;
}

// AES Encryption Round Functions
void subBytes(vector<vector<string>>& state)
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			int num = stoi(state[i][j], nullptr, 16);
			int row = (num & 0xF0) >> 4;
			int col = num & 0x0F;
			int sboxValue = sbox[row][col];

			char buffer[3];
			sprintf_s(buffer, sizeof(buffer), "%02X", sboxValue);
			state[i][j] = buffer;
		}
	}
}

void shiftRows(vector<vector<string>>& state)
{
	// Row 0: no shift
	// Row 1: left shift by 1
	string temp1 = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp1;

	// Row 2: left shift by 2
	swap(state[2][0], state[2][2]);
	swap(state[2][1], state[2][3]);

	// Row 3: left shift by 3 (or right shift by 1)
	string temp3 = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = state[3][0];
	state[3][0] = temp3;
}

// MixColumns multiplication matrix
const unsigned char mixColMatrix[4][4] =
{
	{0x02, 0x03, 0x01, 0x01},
	{0x01, 0x02, 0x03, 0x01},
	{0x01, 0x01, 0x02, 0x03},
	{0x03, 0x01, 0x01, 0x02}
};

unsigned char galoisMultiply(unsigned char a, unsigned char b)
{
	unsigned char p = 0;
	for (int i = 0; i < 8; i++)
	{
		if (b & 1) p ^= a;
		bool hi_bit = a & 0x80;
		a <<= 1;
		if (hi_bit) a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
		b >>= 1;
	}
	return p;
}

void mixColumns(vector<vector<string>>& state)
{
	for (int col = 0; col < 4; col++)
	{
		unsigned char column[4], result[4];

		for (int i = 0; i < 4; i++)
		{
			column[i] = static_cast<unsigned char>(stoi(state[i][col], nullptr, 16));
		}

		for (int i = 0; i < 4; i++)
		{
			result[i] =
				galoisMultiply(mixColMatrix[i][0], column[0]) ^
				galoisMultiply(mixColMatrix[i][1], column[1]) ^
				galoisMultiply(mixColMatrix[i][2], column[2]) ^
				galoisMultiply(mixColMatrix[i][3], column[3]);
		}

		for (int i = 0; i < 4; i++)
		{
			char buffer[3];
			sprintf_s(buffer, sizeof(buffer), "%02X", result[i]);
			state[i][col] = buffer;
		}
	}
}

void addRoundKey(vector<vector<string>>& state, const vector<string>& roundKey)
{
	for (int col = 0; col < 4; col++)
	{
		for (int row = 0; row < 4; row++)
		{
			int stateByte = stoi(state[row][col], nullptr, 16);
			int keyByte = stoi(roundKey[col].substr(row * 2, 2), nullptr, 16);
			int result = stateByte ^ keyByte;

			char buffer[3];
			sprintf_s(buffer, sizeof(buffer), "%02X", result);
			state[row][col] = buffer;
		}
	}
}

// Main AES Encryption with 10 rounds
vector<vector<string>> aesEncrypt(const vector<vector<string>>& plaintext,
	const vector<string>& roundKeys)
{
	vector<vector<string>> state = plaintext;

	// Initial round (round 0)
	addRoundKey(state, vector<string>
	{
		roundKeys[0].substr(0, 8),
			roundKeys[0].substr(8, 8),
			roundKeys[0].substr(16, 8),
			roundKeys[0].substr(24, 8)
	});

	// 9 main rounds
	for (int round = 1; round <= 9; round++)
	{
		subBytes(state);
		shiftRows(state);
		mixColumns(state);

		addRoundKey(state, vector<string>
		{
			roundKeys[round].substr(0, 8),
				roundKeys[round].substr(8, 8),
				roundKeys[round].substr(16, 8),
				roundKeys[round].substr(24, 8)
		});
	}

	// Final round (no MixColumns)
	subBytes(state);
	shiftRows(state);

	addRoundKey(state, vector<string>
	{
		roundKeys[10].substr(0, 8),
			roundKeys[10].substr(8, 8),
			roundKeys[10].substr(16, 8),
			roundKeys[10].substr(24, 8)
	});

	return state;
}
// Helper function to convert string to hexadecimal
string stringToHex(const string& input)
{
	stringstream hexStream;
	for (char c : input)
	{
		hexStream << hex << setw(2) << setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
	}
	return hexStream.str();
}

// Helper function to pad plaintext to 16-byte blocks
vector<string> padPlaintext(const string& plaintext)
{
	vector<string> blocks;
	string hexText = stringToHex(plaintext);

	// Pad with zeros if not multiple of 32 (16 bytes in hex)
	size_t padding = (32 - (hexText.length() % 32)) % 32;
	hexText += string(padding, '0');

	// Split into 32-character (16-byte) blocks
	for (size_t i = 0; i < hexText.length(); i += 32)
	{
		blocks.push_back(hexText.substr(i, 32));
	}

	return blocks;
}

// Inverse S-Box for decryption
unsigned char inv_sbox[16][16] =
{
	{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
	{0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
	{0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
	{0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
	{0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
	{0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
	{0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
	{0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
	{0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
	{0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
	{0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
	{0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
	{0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
	{0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
	{0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
	{0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};

// Inverse MixColumns matrix
const unsigned char invMixColMatrix[4][4] =
{
	{0x0E, 0x0B, 0x0D, 0x09},
	{0x09, 0x0E, 0x0B, 0x0D},
	{0x0D, 0x09, 0x0E, 0x0B},
	{0x0B, 0x0D, 0x09, 0x0E}
};

// Inverse SubBytes operation
void invSubBytes(vector<vector<string>>& state)
{
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			int num = stoi(state[i][j], nullptr, 16);
			int row = (num & 0xF0) >> 4;
			int col = num & 0x0F;
			int invSboxValue = inv_sbox[row][col];

			char buffer[3];
			sprintf_s(buffer, sizeof(buffer), "%02X", invSboxValue);
			state[i][j] = buffer;
		}
	}
}

// Inverse ShiftRows operation
void invShiftRows(vector<vector<string>>& state)
{
	// Row 0: no shift
	// Row 1: right shift by 1
	string temp1 = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = temp1;

	// Row 2: right shift by 2
	swap(state[2][0], state[2][2]);
	swap(state[2][1], state[2][3]);

	// Row 3: right shift by 3 (or left shift by 1)
	string temp3 = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = temp3;
}

// Inverse MixColumns operation
void invMixColumns(vector<vector<string>>& state)
{
	for (int col = 0; col < 4; col++)
	{
		unsigned char column[4], result[4];

		for (int i = 0; i < 4; i++)
		{
			column[i] = static_cast<unsigned char>(stoi(state[i][col], nullptr, 16));
		}

		for (int i = 0; i < 4; i++)
		{
			result[i] =
				galoisMultiply(invMixColMatrix[i][0], column[0]) ^
				galoisMultiply(invMixColMatrix[i][1], column[1]) ^
				galoisMultiply(invMixColMatrix[i][2], column[2]) ^
				galoisMultiply(invMixColMatrix[i][3], column[3]);
		}

		for (int i = 0; i < 4; i++)
		{
			char buffer[3];
			sprintf_s(buffer, sizeof(buffer), "%02X", result[i]);
			state[i][col] = buffer;
		}
	}
}

// Main AES Decryption with 10 rounds
vector<vector<string>> aesDecrypt(const vector<vector<string>>& ciphertext,
	const vector<string>& roundKeys)
{
	vector<vector<string>> state = ciphertext;

	// Initial round (round 10)
	addRoundKey(state, vector<string>
	{
		roundKeys[10].substr(0, 8),
			roundKeys[10].substr(8, 8),
			roundKeys[10].substr(16, 8),
			roundKeys[10].substr(24, 8)
	});

	// 9 main rounds
	for (int round = 9; round >= 1; round--)
	{
		invShiftRows(state);
		invSubBytes(state);
		addRoundKey(state, vector<string>
		{
			roundKeys[round].substr(0, 8),
				roundKeys[round].substr(8, 8),
				roundKeys[round].substr(16, 8),
				roundKeys[round].substr(24, 8)
		});
		invMixColumns(state);
	}

	// Final round (no InvMixColumns)
	invShiftRows(state);
	invSubBytes(state);
	addRoundKey(state, vector<string>
	{
		roundKeys[0].substr(0, 8),
			roundKeys[0].substr(8, 8),
			roundKeys[0].substr(16, 8),
			roundKeys[0].substr(24, 8)
	});

	return state;
}

// Helper function to convert hex to string
string hexToString(const string& hex)
{
	string result;
	for (size_t i = 0; i < hex.length(); i += 2)
	{
		string byteString = hex.substr(i, 2);
		char byte = static_cast<char>(stoi(byteString, nullptr, 16));
		result += byte;
	}
	return result;
}

int main()
{
	int choice;
	string key, text;

	do {
		cout << "\nAES Encryption/Decryption Menu\n";
		cout << "1. Encrypt\n";
		cout << "2. Decrypt\n";
		cout << "3. Exit\n";
		cout << "Enter your choice (1-3): ";
		cin >> choice;
		cin.ignore(); // Clear the newline character

		switch (choice) {
		case 1: // Encryption
		{
			// Key input
			cout << "\nEnter the 128-bit key in hexadecimal format (32 characters, e.g., 2B7E151628AED2A6ABF7158809CF4F3C): ";
			getline(cin, key);
			for (char& c : key) c = toupper(c);
			while (!validateInputKey(key))
			{
				cout << "\nInvalid key! Please re-enter the key: ";
				getline(cin, key);
				for (char& c : key) c = toupper(c);
			}

			// Plaintext input
			cout << "Enter the plaintext to encrypt: ";
			getline(cin, text);

			// Process plaintext
			vector<string> blocks = padPlaintext(text);
			vector<string> roundKeys = expandKey(key);

			cout << "\nEncrypted blocks:\n";
			for (const string& block : blocks)
			{
				vector<vector<string>> state = initializeState(block);
				vector<vector<string>> encryptedState = aesEncrypt(state, roundKeys);

				// Store encrypted block
				string encryptedBlock;
				for (int col = 0; col < 4; col++)
				{
					for (int row = 0; row < 4; row++)
					{
						encryptedBlock += encryptedState[row][col];
					}
				}
				cout << "Block: " << encryptedBlock << endl;
			}
			break;
		}

		case 2: // Decryption
		{
			// Key input
			cout << "\nEnter the 128-bit key in hexadecimal format (32 characters, e.g., 2B7E151628AED2A6ABF7158809CF4F3C): ";
			getline(cin, key);
			for (char& c : key) c = toupper(c);
			while (!validateInputKey(key))
			{
				cout << "\nInvalid key! Please re-enter the key: ";
				getline(cin, key);
				for (char& c : key) c = toupper(c);
			}

			// Ciphertext input (hex format)
			cout << "Enter the ciphertext in hexadecimal format: ";
			getline(cin, text);
			// Remove any whitespace from the ciphertext
			text.erase(remove_if(text.begin(), text.end(), ::isspace), text.end());

			// Process ciphertext
			vector<string> blocks;
			// Split into 32-character (16-byte) blocks
			for (size_t i = 0; i < text.length(); i += 32)
			{
				blocks.push_back(text.substr(i, 32));
			}

			vector<string> roundKeys = expandKey(key);

			cout << "\nDecrypted blocks:\n";
			for (const string& block : blocks)
			{
				vector<vector<string>> state = initializeState(block);
				vector<vector<string>> decryptedState = aesDecrypt(state, roundKeys);

				// Convert decrypted state to string
				string decryptedHex;
				for (int col = 0; col < 4; col++)
				{
					for (int row = 0; row < 4; row++)
					{
						decryptedHex += decryptedState[row][col];
					}
				}
				string decryptedText = hexToString(decryptedHex);
				cout << "Block: " << decryptedText << endl;
			}
			break;
		}

		case 3: // Exit
			cout << "Exiting program...\n";
			break;

		default:
			cout << "Invalid choice! Please enter 1, 2, or 3.\n";
		}
	} while (choice != 3);

	return 0;
}