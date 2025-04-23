/*
 * P1 SAMPLE SERVER
 * ---------------
 * Author: Thoshitha Gamage
 * Date: 01/29/2025
 * License: MIT License
 * Description: This is a sample code for CS447 Spring 2025 P1 server code.
 */

#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <cerrno>
#include <system_error>
#include <fstream>
#include <algorithm>
#include <array>
#include <optional>
#include <filesystem>
#include <format>
#include <thread>
#include <chrono>
#include "p1_helper.h"

#include <unordered_map>
#include <vector>

#define BACKLOG 10
#define MAXDATASIZE 100

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cmath>
#include "server.h"
#include <mutex>

/*
 * Project 3 notes:
 * Use OpenSSL 3.2.2's SSL_CTX functions to configure the TLS context:
 * SSL_CTX_set_min_proto_version() and SSL_CTX_set_max_proto_version() to set the protocol version exclusively to TLS 1.3
 * SSL_CTX_set_ciphersuites()
 * 
 * 
 *
 */

// ! FIX core dump issue when closing connection to client on sending password

/*
* Concurrency ideas:
* Implement semaphores which are shared between threads
* #include <semaphore.h>
* int sem_post and sem_wait functions
*
* Implement multithreading
* 1. Create thread for each connection
* 2. use mutexes to ensure thread synchronizatio
* 3. Create a thread pool
*
* Implementing the rating system - 
* can implement a hashmap separate from the client games
*/

/* 
* Personal notes
* - The goal of the project is to further understand socket API
* Core functionalities:
* BROWSE Mode
* - search for games by title, platform, genre, or rating
* RENT Mode:
* - check out a game, and/or return a game
* MYGAMES Mode
* - Allows you to view the rental history, receive personalized recs,
* and rate previously rented games
* 
* Server should accept requests from TCP clients
* Server should support concurrency
* 
* Implement for client:
* HELO,
* HELP,
* BROWSE (210 code)
*  1. LIST (250 code, 304 if no video games available)
*  2. SEARCH (250, 304 if no games matching criteria)
*  3. SHOW (250, 404 if the game is not found)
* RENT (220 code)
*  1. CHECKOUT (250 for ok, 403 if game unavailable, 404 if game not found)
*  2. RETURN (250 if successfull, 404 if the video game not checked out)
* MYGAMES
*  1. HISTORY (250 ok, 304 if no rental history found)
*  2. RECOMMEND (250 ok, 404 for error)
*  3. RATE (250 ok, 400 for invalid rating)
* BYE - 200 OK - can issue *anytime*
* 
* Server reply codes: 
* 200/210/220/230 for command success
* 304 NO CONTENT for successful request but nothing to send back
* 250 <data> for sucessfuly request with data return
* 400 BAD REQUEST - server could not understand due to invalid syntax or missing params
* 403 FORBIDDEN - indicates server understood the req but refuses to fulfill
* 404 NOT FOUND - server did not the find request resource
* 500 INTERNAL SERVER ERROR - server encountered an unexpected condition
* 
* The server should be capable of handling multiple simultaneous 
* client connections (hence concurrency).
* You have the flexibility to achieve this using either 
* multi-threading techniques or the fork() system call.
*/


// !Implement Mutex locking
// I am pretty sure this works, but I honestly don't fully understand Mutex
std::mutex mtx;
std::array<unsigned char, 16> globalTestSalt; // this is for testing...
std::array<unsigned char, 32> globalTestHash; // this is for testing...

bool srandInit = false;

SSL_CTX* initSSLContext() {
    // SSL_library_init();
    // OpenSSL_add_ssl_algorithms();
    // SSL_load_error_strings();
    const SSL_METHOD* method = TLS_method();
    SSL_CTX* context = SSL_CTX_new(method);
    if (!context) {
        exit(1);
    }
    if (!SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) || 
        !SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION)) {

        SSL_CTX_free(context);
        exit(1);
    }

    std::cout << "context initialized" << std::endl;
    return context;
}

void initCipherSuites(SSL_CTX* context) {
    const char* TLSCiphers = "TLS_AES_256_GCM_SHA384";
    int setCipherSuites = SSL_CTX_set_ciphersuites(context, TLSCiphers);
    if (setCipherSuites != 1) exit(1);
    std::cout << "cipher suite initialized" << std::endl;
}

void validateCertAndKey(SSL_CTX* context) {
    if (SSL_CTX_use_certificate_file(context, "p3server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(context, "p3server.key", SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(context)) {
        SSL_CTX_free(context);
        exit(1);
    }
    // std::cout << "private key matches cert" << std::endl;
}

SSL* initSSLSocket(SSL_CTX* context, int socket) {
    SSL* SSLConnect = SSL_new(context);
    std::cout << "SSLConnect pointer: " << SSLConnect << std::endl;

    if (SSL_set_fd(SSLConnect, socket) != 1) {
        std::cout << "failed to set file descriptor" << std::endl;
        SSL_free(SSLConnect);
        exit(1);
    }

    int acceptStatus = SSL_accept(SSLConnect);
    std::cout << "SSLConnect pointer: " << SSLConnect << std::endl;

    if (acceptStatus > 0) return SSLConnect;
    std::cout << "SSLConnect pointer before free: " << SSLConnect << std::endl;
    SSL_free(SSLConnect);
    std::cout << "SSL_free called" << std::endl;
    exit(1);   
}



// references https://www.geeksforgeeks.org/how-to-read-from-a-file-in-cpp/
std::vector<std::string> readPassFile(const std::filesystem::path &path) {
    std::ifstream file(path);

    std::vector<std::string> text;
    std::string line;

    while (std::getline(file, line)) {
        text.push_back(line);
    }
    file.close();
    return text;
}


std::string findUserFromFile(std::string userName) {
    const std::string dir = ".";
    const std::string path = dir + "/.games_shadow";
    std::vector<std::string> users = readPassFile(path);

    // std::cout << "Users in file: " << std::endl;
    // for (auto &user: users) {
    //     std::cout << user << std::endl;
    // }

    if (users.empty()) return "User not found";

    std::string foundUser = "";
    bool userFound = false; // bad naming
    for (auto& user : users) {
        // std::cout << user << "\n" << std::endl;
        size_t i = user.find_first_of(":$");
        if (i != std::string::npos && user.substr(0, i) == userName) {
            // std::cout << "User name entered in function: " << userName << std::endl;
            foundUser = user;
            userFound = true;
            // std::cout << "User was found" << std::endl;
            break;
        }
    }

    if (!userFound) return "User not found";
    if (foundUser.empty()) {
        // std::cout << "user empty" << std::endl;
        return "User not found";
    }
    return foundUser;
}


void createPassFile() {
    const std::string dir = ".";
    const std::string path = dir + "/.games_shadow";
    if (std::filesystem::exists(path)) std::filesystem::remove(path);

    std::filesystem::create_directories(dir);
    std::ofstream out(path, std::ios::out); 
    if (out.is_open()) {
        out.close();
    }
}


void writeToPassFile(std::string entry) {
    // std::cout << "writing user to file" << std::endl;
    const std::string dir = ".";
    const std::string path = dir + "/.games_shadow";

    std::ofstream out(path, std::ios::app); 
    if (out.is_open()) {
        out << entry + "\n"; // don't forget to parse out newline
        out.close();
    }
}


// taken from my project 2 and extended upon
// convert password strength check to is own function
// implement CSPRNG
std::tuple<std::array<unsigned char, 16>, std::string> genPass() {
    std::string chars;
    size_t stringLength;

    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*_-+=."; 
    stringLength = 8;

    // use for CSPRNG
    // std::uint_least32_t seed;    
    // sysrandom(&seed, sizeof(seed));
    // std::mt19937 gen(seed);
    RAND_poll();
    std::array<unsigned char, 16> salt;
    RAND_bytes(salt.data(), salt.size());


    // deprecating, does not conform to CSPRNG expectation
    // std::string rand;
    // if (!srandInit) {
    //     std::srand(std::time(0));
    //     srandInit = true;
    // }
    std::string rand;

    bool containsUpper = false;
    bool containsLower = false;
    bool containsSymbol = false;
    bool containsNum = false;
    while (true) {
        for (size_t i = 0; i < stringLength; i++) {
            unsigned char randIdx;
            RAND_bytes(&randIdx, 1);
            rand += chars[randIdx % chars.size()];
        }
        if (std::any_of(rand.begin(), rand.begin() + 1, [](char c) {
            return std::string("!@#$%&*_-+=.").find(c) != std::string::npos;
        })) {
            // invalid password
            rand = "";
            continue;
        }
        if (std::any_of(rand.begin(), rand.end(), [](char c) {
            return std::string("!@#$%&*_-+=.").find(c) != std::string::npos;
        })) {
            containsSymbol = true;
        }
        if (std::any_of(rand.begin(), rand.end(), [](char c) {
            return std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ").find(c) != std::string::npos;
        })) {
            containsUpper = true;
        }
        if (std::any_of(rand.begin(), rand.end(), [](char c) {
            return std::string("abcdefghijklmnopqrstuvwxyz").find(c) != std::string::npos;
        })) {
            containsLower = true;
        }
        if (std::any_of(rand.begin(), rand.end(), [](char c) {
            return std::string("0123456789").find(c) != std::string::npos;
        })) {
            containsNum = true;
        }

        if (!(containsLower && containsNum && containsUpper && containsSymbol)) {
            rand = "";
            continue;
        } else {
            // std::cout << rand << std::endl;
            return { salt, rand };
        }
    }
}

std::array<unsigned char, 32> genPassHash(std::tuple<std::array<unsigned char, 16>, std::string> saltAndPass) {
    const int iters = 10000;
    // const int keySize = 32;
    std::array<unsigned char, 32> hash;

    PKCS5_PBKDF2_HMAC(
        std::get<1>(saltAndPass).c_str(),
        static_cast<int>(std::get<1>(saltAndPass).length()),
        std::get<0>(saltAndPass).data(),
        static_cast<int>(std::get<0>(saltAndPass).size()),
        iters,
        EVP_sha256(),
        static_cast<int>(hash.size()),
        hash.data()
    );
    
    return hash;
}

// The password must include at least one uppercase letter (A-Z), at least one lowercase letter (a-z), at
// least one number (0-9
std::tuple<bool, std::string> getUser(std::vector<std::string> cmd) {   
    if (cmd[0] != "USER") return  { false, "" };
    if (!(cmd.size() == 2)) return {false, ""};
    std::string user = cmd[1];
    std::string password;

    bool userExists = false;

    std::string userFromFile = findUserFromFile(user);
    if (userFromFile != "User not found") userExists = true;
    // std::cout << userExists << std::endl;
    // std::cout << userFromFile << std::endl;

    std::tuple<std::array<unsigned char, 16>, std::string> saltAndPass;
    if (!userExists) {
        saltAndPass = genPass();
        const unsigned char* salt;
        salt = std::get<0>(saltAndPass).data();
        std::copy(salt, salt + globalTestSalt.size(), globalTestSalt.begin());
        
        password = std::get<1>(saltAndPass);
        // std::cout << "password: " << password << std::endl;
        // std::cout << "Able to get salt and pass" << std::endl;
    
        std::array<unsigned char, 32> hash = genPassHash(saltAndPass);
        std::copy(std::begin(hash), std::end(hash), globalTestHash.begin());
    
        // std::cout << "able to produce hash" << std::endl;

        std::string modCryptStore;
        modCryptStore += user + ":$"; // username
        modCryptStore += "pkbdf2-sha256$"; // PRF used
        modCryptStore += "10000$"; // num iterations

        // std::cout << std::get<0>(saltAndPass).size() << std::endl;
        std::vector<unsigned char> base64Salt(int(4 * ceil(16.0 / 3.0)) + 1, '\0');
        EVP_EncodeBlock(base64Salt.data(), salt, 16);
        modCryptStore += std::string(reinterpret_cast<char*>(base64Salt.data())) + "$";

        std::vector<unsigned char> base64Hash(int(4 * ceil(32.0 / 3.0)) + 1, '\0');
        EVP_EncodeBlock(base64Hash.data(), hash.data(), 32);
        modCryptStore += std::string(reinterpret_cast<char*>(base64Hash.data()));

        // std::cout << modCryptStore << std::endl;

        // EVPDecodeSalt(base64Salt, saltAndPass);
        // std::cout << "in getUser, writing to file" << std::endl;
        writeToPassFile(modCryptStore);
    } 
    
    return { userExists, password };
}

/*
* used https://github.com/openssl/openssl/issues/17197 as a loose reference
* (mostly what it looks like to use EVP_DecodeUpdate and EVP_DecodeFinal)
*/
std::array<unsigned char, 16> EVPDecodeSalt(std::vector<unsigned char> &base64Salt) {
    EVP_ENCODE_CTX *context = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(context);
    std::vector<unsigned char> decodedSalt(16);
    int decodeLength = 0;
    // int finalDecodeLength = 0;

    EVP_DecodeUpdate(context, decodedSalt.data(), &decodeLength, base64Salt.data(), base64Salt.size());
    // EVP_DecodeFinal(context, decodedSalt.data() + decodeLength, &finalDecodeLength); // may not be necessary

    // std::cout << "decode length: " << decodeLength << " finalDecodeLength: " << finalDecodeLength << std::endl;
    // decodeLength += finalDecodeLength;
    decodedSalt.resize(decodeLength);
    EVP_ENCODE_CTX_free(context);

    // mostly due to my own laziness
    std::array<unsigned char, 16> saltArr;
    std::copy(decodedSalt.begin(), decodedSalt.end(), saltArr.begin());
    return saltArr;
    // std::cout << base64Salt.size() << std::endl; // size: consistently 24
    // std::cout << decodedSalt.size() << std::endl; // size: consistently 16
    // if (std::equal(std::get<0>(saltAndPass).begin(), std::get<0>(saltAndPass).end(), decodedSalt.begin()))
    // {
    //     std::cout << "decoded salt matches" << std::endl;
    // }
    // else
    // {
    //     std::cout << "decoded salt does not match" << std::endl;
    // }
}

std::array<unsigned char, 32> EVPDecodeHash(std::vector<unsigned char> &base64Hash) {
    EVP_ENCODE_CTX *context = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(context);
    std::vector<unsigned char> decodedHash(32);
    int decodeLength = 0;
    // int finalDecodeLength = 0;

    EVP_DecodeUpdate(context, decodedHash.data(), &decodeLength, base64Hash.data(), base64Hash.size());
    // EVP_DecodeFinal(context, decodedSalt.data() + decodeLength, &finalDecodeLength); // may not be necessary

    // std::cout << "decode length: " << decodeLength << " finalDecodeLength: " << finalDecodeLength << std::endl;
    // decodeLength += finalDecodeLength;
    decodedHash.resize(decodeLength);
    EVP_ENCODE_CTX_free(context);

    // mostly due to my own laziness
    std::array<unsigned char, 32> hashArr;
    std::copy(decodedHash.begin(), decodedHash.end(), hashArr.begin());
    return hashArr;
  
}

std::string validateUser(std::string currentUser, std::string pass) {
    // std::cout << "Is user empty? " << currentUser.empty() << std::endl;
    std::string userInfo = findUserFromFile(currentUser);

    // std::cout << "User found: " << userInfo << std::endl;
    size_t delimAfterUser = userInfo.find(":$");
    size_t delimAfterPrf = userInfo.find("$", delimAfterUser + 2);
    size_t delimAfterNumIter = userInfo.find("$", delimAfterPrf + 1);
    size_t delimAfterSalt = userInfo.find("$", delimAfterNumIter + 1);

    std::string prf = userInfo.substr(delimAfterUser + 2, delimAfterPrf - delimAfterUser - 2);
    std::string numIter = userInfo.substr(delimAfterPrf + 1, delimAfterNumIter - delimAfterPrf - 1);
    std::string salt = userInfo.substr(delimAfterNumIter + 1, delimAfterSalt - delimAfterNumIter - 1);
    std::string hash = userInfo.substr(delimAfterSalt + 1, userInfo.size() - 2);

    std::cout << "PRF: " << prf << std::endl;
    std::cout << "NUM ITER: " << numIter << std::endl;
    std::cout << salt << std::endl;

    std::cout << "SALT BEFORE DECODE " << salt << std::endl;
    std::vector<unsigned char> base64Salt(salt.begin(), salt.end());
    std::array<unsigned char, 16> decodedSalt = EVPDecodeSalt(base64Salt);

    std::cout << "HASH BEFORE DECODE " << hash << std::endl;
    std::vector<unsigned char> base64Hash(hash.begin(), hash.end());
    std::array<unsigned char, 32> decodedHash = EVPDecodeHash(base64Hash);

    if (!hash.empty() && hash.back() == '\n') {
        hash.pop_back();
        std::cout << "HASH had a newline at the end and it was removed." << std::endl;
    }

    // std::cout << "HASH AFTER DECODING PROCESS ";
    // for (const auto& byte : decodedHash) {
    //     std::cout << std::hex << static_cast<int>(byte);
    // }

    std::array<unsigned char, 32> generatedHash;
    if (!pass.empty() && pass.back() == '\n') {
        pass.pop_back();
        std::cout << "PASS had a newline at the end and it was removed." << std::endl;
    }
    std::cout << "PASS ENTERED " << pass << std::endl;

    PKCS5_PBKDF2_HMAC(
        pass.c_str(),
        static_cast<int>(pass.length()),
        decodedSalt.data(),
        static_cast<int>(decodedSalt.size()),
        std::stoi(numIter),
        EVP_sha256(),
        static_cast<int>(generatedHash.size()),
        generatedHash.data()
    );
    std::cout << "GENERATED HASH ";
    for (const auto& byte : generatedHash) {
        std::cout << std::hex << static_cast<int>(byte);
    }
    std::cout << std::endl;


    if (generatedHash == decodedHash) {
        std::cout << "PASSWORD validated" << std::endl;
        return "210 SUCCESS: Authentication successful";
    } else {
        std::cout << "it doesn't match" << std::endl;
        return "410 FAILED: Authentication failed";
    }
   
    // // good stuff
    // // if (decodedSalt == globalTestSalt) {
    // //     std::cout << "SALT CORRECTLY DECODED" << std::endl;
    // // }
    // if (decodedHash == globalTestHash) {
    //     std::cout << "HASH CORRECTLY DECODED" << std::endl;
    // }


   

    // return "Yes";
}




/*
* Provides HELP output... kind of a dumb way of doing it, but it is easiest.
*/
std::string helpStr(std::string state) {
    std::string help;
    if (state == "standard") {
        help = "Available commands:\nBROWSE - Starts browse mode, allowing user to run:\n\t1. LIST <filter> - the filter option can be either: title, platform, genre, rating.\n\t2. SEARCH <filter> <keyword> - same options for filter as above, with an additional keyword option to reduce query width.\n\t3. SHOW <game_id> [availability] - display details for the game with specified game_id. If [availability] included, only available copies are listed\nRENT - Starts rent mode, allows user to checkout and return videogames:\t1. CHECKOUT <game_id> - allows user to checkout a videogame from the system, updating DB.\n\t2. RETURN <game_id> - allows user to return their checkedout videogame from the system, updating DB.\nMYGAMES - Starts mygames mode, allowing user to manage rented games and explore recommendtions:\n\t1. HISTORY - displays full client rental history if existing.\n\t2. RECOMMEND <filter> - the filter option can be either: platform or genre. The command returns recommendations based on this filter.\n\t3. RATE <game_id> <rating> - user can rate specified game with game_id and provide a rating between 1 and 10 (integer)\nBYE - command to end interaction with the server.\n";
    }
    else if (state == "browse") {
        help = "Available commands:\n1. LIST <filter> - the filter option can be either: title, platform, genre, rating.\n2. SEARCH <filter> <keyword> - same options for filter as above, with an additional keyword option to reduce query width.\n3. SHOW <game_id> [availability] - display details for the game with specified game_id. If [availability] included, only available copies are listed\n";
    }
    else if (state == "rent") {
        help = "Available commands:\n1. CHECKOUT <game_id> - allows user to checkout a videogame from the system, updating DB.\n2. RETURN <game_id> - allows user to return their checkedout videogame from the system, updating DB.\n";
    }
    else if (state == "mygames") {
        help = "Available commands:\n1. HISTORY - displays full client rental history if existing.\n2. RECOMMEND <filter> - the filter option can be either: platform or genre. The command returns recommendations based on this filter.\n3. RATE <game_id> <rating> - user can rate specified game with game_id and provide a rating between 1 and 10 (integer)\n";
    }
    else {
        help = "Failed to fetch help information.";
    }

    return help;
}

// Signal handler for SIGCHLD
void sigchld_handler(int s) {
    (void)s;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

// Get sockaddr, IPv4 or IPv6
void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Convert string to camel case
std::string toCamelCase(const std::string& input) {
    std::string output;
    bool capitalize = true;
    for (char c: input) {
        if (std::isalpha(c)) {
            output += capitalize? std::toupper(c): std::tolower(c);
            capitalize =!capitalize;
        } else {
            output += c;
        }
    }
    return output;
}

// Log events with timestamp
void logEvent(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::cout << "[" << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S") << "] " << message << std::endl;
}

/*
* Splits user input/commands into a vector of
* usable tokens.
* NOTE for Gamage: Adding removal of ending character
*/
std::vector<std::string> splitStr(const std::string& input) {
    std::string output;
    std::vector<std::string> vec;
    // std::cout<< input << std::endl;

    std::string newIn = input;
    while (!newIn.empty() && (newIn.back() == '\r' || newIn.back() == '\n')) {
        newIn.pop_back();
    }
   
    for (char c: newIn) {
        if (c == ' ' && !output.empty()) {
            vec.push_back(output);
            output.clear();
       
        }
        else if (c != ' ') { output += c; }
    }

    // end case, if there is any token left to add after last space
    if (!output.empty()) {
        vec.push_back(output);
    }


    return vec;
}


/*
* References Beej's Guide (Chapter 7 Section 4 Handling Partial send()s)
* https://beej.us/guide/bgnet/html/#sendall
* In cases where the server is attempting to send too many bytes at once,
* the message is broken up into multiple sends
* Need to implement better error handling.
* I thought this was necessary due to a different bug but it wasn't...
*/
int sendAll(SSL* SSLConnect, const std::string& message) {
    std::lock_guard<std::mutex> lock(mtx);
    const char* buf = message.c_str();
    int len = message.size();
    int total = 0;
    int bytesLeft = len;

    while (total < len) {
        int n = SSL_write(SSLConnect, buf + total, bytesLeft);
        if (n <= 0) {
            std::cout << "Error in sendAll" << std::endl;
            return -1;
        }
        total += n;
        bytesLeft -= n;
    }
    return 0;
}

/*
* Builds individual strings per game. I realize I could use format
* but I currently don't know much C++ and am going off of fundamentals.
*/
std::string singleStrBuilder(std::vector<Game> games, int idx, bool isClientGames = false, std::unordered_map<int, int> ratings = {}) {
    std::string buildStr = "";
    buildStr += "ID: " + std::to_string(games[idx].id);
    buildStr += ", Title: " + games[idx].title;
    buildStr += ", Year: " + std::to_string(games[idx].year);
    buildStr += ", Genre: " + games[idx].genre;
    buildStr += ", Platform: " + games[idx].platform;
    buildStr += ", ESRB: " + games[idx].esrb;
   
    if (!isClientGames) {
        if (games[idx].available) {
            buildStr += ", Available: True";
        }
        else {
            buildStr += ", Available: False";
        }
        buildStr += ", # Copies: " + std::to_string(games[idx].copies);
    }

    if (ratings.find(games[idx].id) != ratings.end()) {
        buildStr += ", Rating: " + std::to_string(ratings[games[idx].id]);
    }

    buildStr += "\n";

    return buildStr;
}

/*
* Prints out the entire Games vector cleanly
*/
std::string strBuilder(std::vector<Game> games, bool isClientGames = false, std::unordered_map<int, int> ratings = {}) {
    std::string buildStr = "";
    for (size_t i = 0; i < games.size(); i++) {
        buildStr += singleStrBuilder(games, i, isClientGames, ratings);
    }
    return buildStr;
}

/* 
* SEARCH cmd primary function
* Builds a string that filters based on user input.
* Also handles situations where user makes syntax errors (user will be sent code 503)
* or situations where nothing is found matching a valid search (code 304)
*/
std::string buildGameSearchStr(std::vector<Game> games, std::vector<std::string> cmd, std::unordered_map<int, int> ratings = {}) {
    std::string buildStr = "";
    // For scenarios outside of standard returns
    std::string invalid = "Invalid";
    std::string empty = "Empty";
    // want to check user is searching with a valid filter
    std::string filter = "";
    // // default option: no filter
    // if (cmd.size() == 1) {
    //     buildStr = strBuilder(games);
    // }
    // user did not specify a filter
    if (cmd.size() != 3) {
        return invalid;
    }  

    // Better than a long if statement? Probably not.
    std::vector<std::string> filters = { "title", "platform", "genre", "rating" };
    for (size_t i = 0; i < filters.size(); i++) {
        if (filters[i] == cmd[1]) {
            filter = filters[i];

        }
    }
    if (filter == "") { // if the filter was not found (likely a user typo)
        return invalid;
    }
    
    for (size_t i = 0; i < games.size(); i++) {
        if (filter == "title" && cmd[2] == games[i].title) {
            buildStr += singleStrBuilder(games, i);
        }
        if (filter == "platform" && cmd[2] == games[i].platform) {
            buildStr += singleStrBuilder(games, i);
        }
        else if (filter == "genre" && cmd[2] == games[i].genre) {
            buildStr += singleStrBuilder(games, i);
        }
        // ! IMPLEMENT
        else if (filter == "rating") {
            int ratingIn;
            try {
                ratingIn = std::stoi(cmd[2]);
            } 
            catch (const std::invalid_argument& e) {
                return invalid;
            } 
            catch (const std::out_of_range& e) {
                return invalid;
            }
            if (ratingIn == ratings[games[i].id]) {
                buildStr += singleStrBuilder(games, i);
            }
        }
    }

    if (buildStr == "") {
        return empty;
    }

    return buildStr;
}

/* 
* Sorts games by title, platform, genre, or rating. 
* Handles both the client games vector and ratings map...
*/
std::vector<Game> sortGames(std::vector<Game> games, std::string sortBy, std::unordered_map<int, int> ratings = {}) {
    if (sortBy == "title") {
        std::sort(games.begin(), games.end(), [](Game a, Game b) {
            return a.title < b.title;
            }
        );
    } else if (sortBy == "platform") {
        std::sort(games.begin(), games.end(), [](Game a, Game b) {
            return a.platform < b.platform;
            }
        );
    } else if (sortBy == "genre") {
        std::sort(games.begin(), games.end(), [](Game a, Game b) {
                return a.genre < b.genre;
            }
        );
    } else if (sortBy == "rating") {
        std::sort(games.begin(), games.end(), [&ratings](Game a, Game b) {
                return ratings[a.id] > ratings[b.id];
            }
        );
    }
    return games;
}


/*
* LIST allows the client to list all games from the database,
* with an optional filter to sort the games by title, platform, genre, or rating.
*/
std::string buildListStr(std::vector<Game> games, std::vector<std::string> cmd, std::unordered_map<int, int> ratings = {}) {
    std::string buildStr = "";
    std::string invalid = "Invalid";
    std::string empty = "Empty";

    if (cmd.size() > 2) {
        return invalid;
    }
    if (cmd.size() == 1) {
        for (size_t i = 0; i < games.size(); i++) {
            buildStr += "ID: " + std::to_string(games[i].id);
            buildStr += ", Title: " + games[i].title;
            buildStr += ", Year: " + std::to_string(games[i].year);
            buildStr += ", Genre: " + games[i].genre;
            buildStr += ", Platform: " + games[i].platform;
            buildStr += ", ESRB: " + games[i].esrb;
            if (games[i].available) {
                buildStr += ", Available: True";
            }
            else {
                buildStr += ", Available: False";
            }
            buildStr += ", # Copies: " + std::to_string(games[i].copies);
            if (ratings.find(games[i].id) != ratings.end()) {
                buildStr += ", Rating: " + std::to_string(ratings[games[i].id]);
            }
            buildStr += "\n";
        }
    }   

    // filter/sort by cmd 2
    if (cmd.size() == 2) {
        // again, could've used a long if statement but...
        int validFilter = false;
        std::vector<std::string> filters = { "title", "platform", "genre", "rating" };
        for (size_t i = 0; i < filters.size(); i++) {
            if (filters[i] == cmd[1]) {
                validFilter = true;
            }
        }
        if (!validFilter) return invalid;
        std::vector<Game> filteredGames = sortGames(games, cmd[1], ratings);
        buildStr = strBuilder(filteredGames, false, ratings);
    }
    return buildStr;
}

/* 
* SHOW command primary function 
*/
std::string buildShowStr(std::vector<Game> games, std::vector<std::string> cmd) {
    std::string invalid = "Invalid";
    std::string empty = "Empty";
    std::string buildStr = "";
    int id;
    if(cmd.size() < 1 || cmd.size() > 3) {
        return invalid;
    }
    if (cmd.size() == 2) {

        try {
            id = std::stoi(cmd[1]);
        } catch (const std::invalid_argument& e) {
            return invalid;
        } catch (const std::out_of_range& e) {
            return invalid;
        }
        
        // idk how vectors work in C++. I feel like this is not ideal
        for (size_t i = 0; i < games.size(); i++) {
            if (id == games[i].id) {
                buildStr += singleStrBuilder(games, i); // slow probably
                break; 
            }
        }
    }

    if (cmd.size() == 3) {
        try {
            id = std::stoi(cmd[1]);
        } 
        catch (const std::invalid_argument& e) {
            return invalid;
        } 
        catch (const std::out_of_range& e) {
            return invalid;
        }
        if (!(cmd[2] == "availability")) {
            return invalid;
        }
        for (size_t i = 0; i < games.size(); i++) {
            if (id == games[i].id) {
                // buildStr += games[i].title + "\n";
                buildStr += std::to_string(games[i].copies) + "\n";
                if (games[i].available) {
                    buildStr += "True\n";
                }
                else {
                    buildStr += "False\n";
                }
                break;
            }
        }
    }

    if (buildStr == "") return empty;
    return buildStr;
}


/*
* Checks out a game ONLY if it is available.
* Changes made by one client can be viewed by all other clients.
* Client checkouts affect what other clients can check out.
*/
std::string checkoutGame(std::vector<Game>& games, std::vector<std::string> cmd, std::vector<Game>& clientGames) {
    std::string invalid = "Invalid";
    std::string empty = "Empty";
    std::string buildStr = "";
    int id;

    // may be editing the games vector.
    // probably could've done this later in the function.
    std::lock_guard<std::mutex> lock(mtx);

    if(cmd.size() != 2) {
        return invalid;
    }

    try {
        id = std::stoi(cmd[1]);
    } 
    catch (const std::invalid_argument& e) {
        return invalid;
    } 
    catch (const std::out_of_range& e) {
        return invalid;
    }
    bool gameFound = false;
    bool checkoutSuccess = false;
    for (size_t i = 0; i < games.size(); i++) {
        if (id == games[i].id) {
            gameFound = true;
            if (games[i].copies == 0) break;
            
            games[i].copies -= 1;
            if (games[i].copies == 0) {
                games[i].available = false;
            }
            checkoutSuccess = true;
            clientGames.push_back(games[i]);
            break;
        }
    }

    if (!gameFound) {
        return empty;
    }
    if (checkoutSuccess) return "250 SUCCESS.";
    return "403 Game unavailable.";
}


/*
* Returns a game IF the user has it checked out.
* Same with checkout, this affects the availability of a game for all clients.
*/
std::string returnGame(std::vector<Game>& games, std::vector<std::string> cmd, std::vector<Game>& clientGames, bool isBye = false) {
    std::string invalid = "Invalid";
    std::string empty = "Empty";
    std::string buildStr = "";

    // may be editing the games vector.
    // probably could've done this later in the function.
    std::lock_guard<std::mutex> lock(mtx);

    int id;
    if(cmd.size() != 2) {
        return invalid;
    }

    try {
        id = std::stoi(cmd[1]);
    } 
    catch (const std::invalid_argument& e) {
        return invalid;
    } 
    catch (const std::out_of_range& e) {
        return invalid;
    }

    bool gameFound = false;

    for (size_t i = 0; i < clientGames.size(); i++) {
        if (clientGames[i].id == id) {
            clientGames.erase(clientGames.begin() + i);
            gameFound = true;
            break;
        }
    }
    if (!gameFound) {
        return empty; // 404 in this case
    }

    for (size_t i = 0; i < games.size(); i++) {
        if (id == games[i].id) {
            gameFound = true;
            if (games[i].copies == 0) {
                games[i].available = true;
            }
            games[i].copies += 1;
            break;
        }
    }
    if (!isBye) return "250 SUCCESS.";
    return "returned";
}

/*
* Returns all games a client has checked out when they run BYE.
* This affect does not happen in the case that a client force kills
* a process.
*/
void cleanOnBye(std::vector<Game>& games, std::vector<Game>& clientGames) {
    for (size_t i = 0; i < clientGames.size(); i++) {
        for (size_t j = 0; j < games.size(); j++) {
            if (clientGames[i].id == games[j].id) {
                if (games[j].copies == 0) {
                    games[j].available = true;
                }
                games[j].copies += 1;
                break;
            }
        }
    }
    clientGames.clear();
}

/* 
* Shows everything a client currently has checked out.
*/
std::string buildHistoryStr(std::vector<Game>& clientGames, std::unordered_map<int, int> ratings) {
    std::string buildStr = "";
    std::string empty = "Empty";

    if (clientGames.size() > 0) {
        buildStr += "250 SUCCESS. History:\n";
    }
    buildStr += strBuilder(clientGames, true, ratings);
    if (buildStr == "") return empty;
    return buildStr;
}

/*
 * Builds recommendations based on user rating history
 * Whichever genre or platform the user has a tendency to rate
 * games higher than a 6 is returned to the usstd::string heloRes = "200 HELO " + std::string(s) + " (TCP)"; er along with the 
 * games the server has from that genre. 
 * If the user does not specify a filter, 
 * then the server returns a random recommendaton
 */
std::string buildRecStr( // ugly formatting
    // ! Filter out games that are already in user collection!!!
    std::vector<Game> games, 
    std::vector<Game> clientGames, 
    std::vector<std::string> cmd,
    std::unordered_map<int, int> ratings
) {
    std::string buildStr = "";
    std::string invalid = "Invalid";
    std::string empty = "Empty";
    std::string filter;

    if (cmd.size() > 2) return invalid;

    if (cmd.size() == 2) {
        filter = cmd[1];
        if (filter != "genre" && filter != "platform") return invalid;
    }
    else { filter = ""; }

    if (filter != "" && (clientGames.size() > 0)) {

        /* 
        * If a user tends to rate games highly in a specific genre
        * or platform, provide the user with games in that 
        * specific genre/platform.
        */
        std::unordered_map<std::string, int> filterOccurences;

        std::vector<int> idsChecked;
        for (size_t i = 0; i < clientGames.size(); i++) {
            if (std::find(idsChecked.begin(), idsChecked.end(), clientGames[i].id) == idsChecked.end()) {
                if (ratings[clientGames[i].id] > 6) {
                    if (filter == "genre") {
                    filterOccurences[clientGames[i].genre]++;
                    }
                    else if (filter == "platform") {
                    filterOccurences[clientGames[i].platform]++;
                    }
                }
                idsChecked.push_back(clientGames[i].id);
            }
        }

        int maxVal = -1;
        std::string maxValKey = "";

        for (const auto& kv : filterOccurences) {
            if (kv.second > maxVal) {
                maxVal = kv.second;
                maxValKey = kv.first;
            }
        }

        // may want to consider also filtering out unavailable games
        buildStr += "250 SUCCESS. We saw you tend to like " + maxValKey;
        buildStr += ", so we found these games for you:\n";
        bool itemFound = false;
        for (size_t i = 0; i < games.size(); i++) {
            if (filter == "genre" && games[i].genre == maxValKey) {
                buildStr += singleStrBuilder(games, i);
                itemFound = true;
            }
            else if (filter == "platform" && games[i].platform == maxValKey) {
                buildStr += singleStrBuilder(games, i);
                itemFound = true;
            }
        }

        if (itemFound) return buildStr;
        else return "404 No worthy recommendations found.";
        // evaluate which genre or platform occurs most
    }

    if (filter == "" && games.size() > 0) {
        int idx = std::rand() % games.size();
        buildStr += "250 SUCCESS. You didn't specify a filter, so we chose a random game you might like:\n";
        buildStr += singleStrBuilder(games, idx);
        return buildStr;
    }
  
    
    return empty;
}

/*
 * Simply allows the user to rate games in a range from 1-10,
 * handling outliers if needed.
*/
std::string rateGame(std::vector<Game> clientGames, std::vector<std::string> cmd, std::unordered_map<int, int>& ratings) {
    std::string invalid = "Invalid";
    std::string empty = "Empty";
    int id;
    int rating;

    if (cmd.size() != 3) return invalid;
    try {
        id = std::stoi(cmd[1]);
        rating = std::stoi(cmd[2]);
    } 
    catch (const std::invalid_argument& e) {
        return invalid;
    } 
    catch (const std::out_of_range& e) {
        return invalid;
    }
    if (rating < 1 || rating > 10) return invalid;

    bool idFound = false;
    for (size_t i = 0; i < clientGames.size(); i++) {
        if (clientGames[i].id == id) {
            idFound = true;
            ratings[id] = rating;
            break;
        }
    }

    if (!idFound) return "400 BAD REQUEST: Invalid rating.";
    return "250 SUCCESS. Rated game.";
}


int main(int argc, char* argv[]) {
    createPassFile(); // initialize the user-password bank
    int sockfd, new_fd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN]; // client addr
    char server_addr[INET6_ADDRSTRLEN]; // server addr

    // used Linux man page https://www.man7.org/linux/man-pages/man2/gethostname.2.html
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));

    int rv;

    // database
    const std::string DB_NAME = "games.db";
    // vector from the database
    std::vector<Game> gamesVec = loadGamesFromFile(DB_NAME);

    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>\n";
        return 1;
    }

    std::string configFileName = argv[1];
    std::optional<std::string> port;

    std::filesystem::path configFilePath(configFileName);
    if (!std::filesystem::is_regular_file(configFilePath)) {
        std::cerr << "Error opening configuration file: " << configFileName << "\n";
        return 1;
    }

    std::ifstream configFile(configFileName);
    std::string line;
    while (std::getline(configFile, line)) {
        std::string_view lineView(line);
        if (lineView.substr(0, 5) == "PORT=") {
            port = lineView.substr(5);
            break;
        }
    }
    configFile.close();

    if (!port.has_value()) {
        std::cerr << "Port number not found in configuration file!\n";
        return 1;
    }

    if ((rv = getaddrinfo(nullptr, port->c_str(), &hints, &servinfo))!= 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << "\n";
        return 1;
    }

    // Loop through all the results and bind to the first we can
    for (p = servinfo; p!= NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            std::perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            throw std::system_error(errno, std::generic_category(), "setsockopt");
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            std::perror("server: bind");
            continue;
        }

        // get server address
        // I thought this was a necessary step, turns out it isn't.
        inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), server_addr, sizeof server_addr);
        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        std::cerr << "server: failed to bind\n";
        return 2;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        throw std::system_error(errno, std::generic_category(), "listen");
    }

    sa.sa_handler = sigchld_handler; // Reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        throw std::system_error(errno, std::generic_category(), "sigaction");
    }

    std::cout << "server: waiting for connections...\n";

    // SSL_CTX* context = initSSLContext();
    const SSL_METHOD* method = TLS_method();
    SSL_CTX* context = SSL_CTX_new(method);
    if (!context) {
        exit(1);
    }
    if (!SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) || 
        !SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION)) {

        SSL_CTX_free(context);
        exit(1);
    }

    std::cout << "context initialized" << std::endl;

    const char* TLSCiphers = "TLS_AES_256_GCM_SHA384";
    int setCipherSuites = SSL_CTX_set_ciphersuites(context, TLSCiphers);
    if (setCipherSuites != 1) exit(1);
    std::cout << "cipher suite initialized" << std::endl;

    if (SSL_CTX_use_certificate_file(context, "p3server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(context, "p3server.key", SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(context)) {
        SSL_CTX_free(context);
        exit(1);
    }
    std::cout << "Cert and key valid" << std::endl;

    // initCipherSuites(context);
    // validateCertAndKey(context);


    while (true) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &sin_size);
        if (new_fd == -1) {
            std::perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);
        logEvent("Connection from: " + std::string(s));



        std::thread clientThread([context, &new_fd, s, server_addr, &gamesVec, hostname]() {
     
            // SSL* SSLConnect = initSSLSocket(context, new_fd);
            SSL* SSLConnect = SSL_new(context);
            if (!SSLConnect) {
                std::cerr << "Failed to create SSL object" << std::endl;
                return;
            }
            std::cout << "SSLConnect pointer: " << SSLConnect << std::endl;

            if (SSL_set_fd(SSLConnect, new_fd) != 1) {
                std::cout << "failed to set file descriptor" << std::endl;
                SSL_free(SSLConnect);
                return;
            }

            int acceptStatus = SSL_accept(SSLConnect);
            if (acceptStatus <= 0) {
                std::cout << "SSL_accept failed" << std::endl;
                ERR_print_errors_fp(stderr);
                SSL_free(SSLConnect);
                return;
            }

            std::cout << "SSLConnect init success" << std::endl;

            

            std::array<char, MAXDATASIZE> buf;
            int numbytes;

            // Some of the common/frequently used codes
            const std::string BAD_SEQ_CODE = "503 BAD SEQUENCE: Bad sequence of commands.";
            const std::string NO_MATCH = "304 NO CONTENT: No video games found matching the filter criteria.";
            const std::string BYE = "200 BYE";



            // manage state (e.g. browse, mygames, or standard)
            std::string state = "standard"; // maybe change to enum

            // has the user completed the HELO 'handshake' ?
            // change to loginInit
            bool heloInit = false;
            bool waitingForPass = false;
            std::string currentUser = "";

            // games the client has successfully checked out
            std::vector<Game> clientGames = std::vector<Game>();

            // unfortunately this was the easiest way to add ratings...
            // makes the code a lot uglier without adding a rating field to Game object
            // key: Game ID, value: rating
            std::unordered_map<int, int> clientRatings = std::unordered_map<int, int>();

            int passwordAttempts = 0;

            while (true) {
                if ((numbytes = SSL_read(SSLConnect, buf.data(), MAXDATASIZE - 1)) == -1) {
                    perror("recv");
                    exit(1);
                } else if (numbytes == 0) {
                    logEvent("Client disconnected: " + std::string(s));
                    break;
                }

                // sendAll(SSLConnect, "test");

                // if (SSLConnect) {
                //     std::cout << "freeing SSLConnect" << std::endl;
                  
                //     SSL_shutdown(SSLConnect);
                 
                //     std::cout << "SSLConnect pointer: " << SSLConnect << std::endl;
                //     ERR_print_errors_fp(stderr);
                //     SSL_free(SSLConnect);
                //     SSLConnect = nullptr;
                //     std::cout << "free succeeded" << std::endl;
                // }
                // else std::cout << "SSLConnect is null" << std::endl;
                // close(new_fd);
                // return;

                buf[numbytes] = '\0';
                std::string receivedMsg(buf.data());
                std::vector<std::string> clientCmdVec = splitStr(receivedMsg);
                std::string cmd = clientCmdVec[0];
                // std::cout << cmd << std::endl;
                // what even is a switch statement? *jokes*

                if (waitingForPass) {
                    passwordAttempts ++;
                    if (cmd == "PASS" && clientCmdVec.size() == 2) {
                        std::cout << currentUser << std::endl;
                        std::string validateRes = validateUser(currentUser, clientCmdVec[1]);
                        if (validateRes == "210 SUCCESS: Authentication successful") {
                            heloInit = true;
                            waitingForPass = false;
                            
                            if (sendAll(SSLConnect, validateRes) == -1) {
                                perror("send");
                            }
                            
                            continue;
                        }
                        else if (validateRes == "410 FAIL: Authentication failed")
                        if (sendAll(SSLConnect, BAD_SEQ_CODE) == -1) {
                                perror("send");
                        }   
                    }
                    else sendAll(SSLConnect, "")

                }
                // allow user to run BYE anytime, even during authentication...
                else if (cmd == "BYE") {
                    // be sure to run a clean up function
                    std::string byeRes = BYE;

                    cleanOnBye(gamesVec, clientGames);
                    if (sendAll(SSLConnect, byeRes) == -1) {
                        perror("send");
                    }
                    heloInit = false;
                    break;
                }
                else if (cmd == "USER" && !heloInit) {
                    // need to return with client addr back to them
                    

                    if (clientCmdVec.size() < 2 || clientCmdVec.size() > 2) {
                        if (sendAll(SSLConnect, "400 Incorrect number of arguments") == -1) {
                            perror("send");
                        }
                        continue;
                    }
                    std::string password;
                    bool userExists;

                    std::tuple<bool, std::string> getUserReturn = getUser(clientCmdVec);

                    // sendAll(SSLConnect, "test in USER");
                    // if (SSLConnect) {
                    //     std::cout << "freeing SSLConnect" << std::endl;
                    
                    //     SSL_shutdown(SSLConnect);
                    
                    //     std::cout << "SSLConnect pointer: " << SSLConnect << std::endl;
                    //     ERR_print_errors_fp(stderr);
                    //     SSL_free(SSLConnect);
                    //     SSLConnect = nullptr;
                    //     std::cout << "free succeeded" << std::endl;
                    // }
                    // else std::cout << "SSLConnect is null" << std::endl;
                    // close(new_fd);
                    // return;

                    userExists = std::get<0>(getUserReturn);
                    password = std::get<1>(getUserReturn);

                    std::cout << password << std::endl;

                    if (state != "standard") state = "standard"; // just reinit state if necessary

                    // sendAll(SSLConnect, "test in USER");
                    // if (SSLConnect) {
                    //     std::cout << "freeing SSLConnect" << std::endl;
                    
                    //     SSL_shutdown(SSLConnect);
                    
                    //     std::cout << "SSLConnect pointer: " << SSLConnect << std::endl;
                    //     ERR_print_errors_fp(stderr);
                    //     SSL_free(SSLConnect);
                    //     SSLConnect = nullptr;
                    //     std::cout << "free succeeded" << std::endl;
                    // }
                    // else std::cout << "SSLConnect is null" << std::endl;
                    // close(new_fd);
                    // return;

                    // user's first time, did not exist in the file
                    if (!userExists && !password.empty()) {
                        std::string passRes = "Your new password is " + password;
                        if (sendAll(SSLConnect, passRes) == -1) {
                            perror("send");
                        }
                      
                        break; 
                    } else if (userExists) {
                        if (sendAll(SSLConnect, "300 Password required") == -1) {
                            perror("send");
                        }
                        waitingForPass = true;
                        // std::cout << "the current user is " << clientCmdVec[1] << std::endl;
                        // std::cout << clientCmdVec[1].size() << std::endl;
                        currentUser = clientCmdVec[1];
                        // wait for PASS command then do authentication protocol
                    }
                    
                } 
                // should only be available if HELO initialized
                else if (heloInit && cmd == "HELP" && clientCmdVec.size() == 1) {
                    std::string helpRes;
                    helpRes = helpStr(state);

                    sendAll(SSLConnect, helpRes);
                }
                else if (heloInit && cmd == "BROWSE" && clientCmdVec.size() == 1) {
                    state = "browse";
                    std::string browseRes = "210 Switched to BROWSE mode.";
                    if (sendAll(SSLConnect, browseRes) == -1) {
                        perror("send");
                    }
                }
                else if (heloInit && cmd == "RENT" && clientCmdVec.size() == 1) {
                    state = "rent";
                    std::string rentRes = "220 Switched to RENT Mode.";
                    if (sendAll(SSLConnect, rentRes) == -1) {
                        perror("send");
                    }
                }
                else if (heloInit && cmd == "MYGAMES" && clientCmdVec.size() == 1) {
                    state = "mygames";
                    std::string myGamesRes = "230 Switched to MYGAMES Mode.";
                    if (sendAll(SSLConnect, myGamesRes) == -1) {
                        perror("send");
                    }
                }
                else if (heloInit && cmd == "SEARCH") { // Done but test
                    // user can initiate 
                    std::string searchRes;
                    if (state == "browse") { // only valid in browse state
                        searchRes = buildGameSearchStr(gamesVec, clientCmdVec, clientRatings);
                        if (searchRes == "Invalid") {
                            searchRes = BAD_SEQ_CODE;
                        }
                        if (searchRes == "Empty") {
                            searchRes = NO_MATCH;
                        }
                    }
                    else {
                        searchRes = BAD_SEQ_CODE;
                    }

                    if (sendAll(SSLConnect, searchRes) == -1) {
                        perror("send");
                    }
                }
                else if (heloInit && cmd == "LIST") { // Need to finish
                    // user can initiate 
                    std::string searchRes;
                    if (state == "browse") { // search is only valid in browse
                        searchRes = buildListStr(gamesVec, clientCmdVec, clientRatings);
                        if (searchRes == "Invalid") {
                            searchRes = BAD_SEQ_CODE;
                        }
                        if (searchRes == "Empty") {
                            searchRes = NO_MATCH;
                        }
                    }
                    else {
                        searchRes = BAD_SEQ_CODE;
                    }
                    if (sendAll(SSLConnect, searchRes) == -1) {
                        perror("send");
                    }
                }
                else if (heloInit && cmd == "SHOW") { // Done but test
                    std::string showRes;
                    if (state == "browse") { // search is only valid in browse
                        showRes = buildShowStr(gamesVec, clientCmdVec);
                         if (showRes == "Invalid") {
                            showRes = BAD_SEQ_CODE;
                        }
                        if (showRes == "Empty") {
                            showRes = NO_MATCH;
                        }
                    }
                    else {
                        showRes = BAD_SEQ_CODE;
                    }
                    if (sendAll(SSLConnect, showRes) == -1) {
                        perror("send");
                    }
                }
                else if (heloInit && cmd == "CHECKOUT") {
                    std::string checkRes;
                    if (state == "rent") { // search is only valid in browse
                        checkRes = checkoutGame(gamesVec, clientCmdVec, clientGames);
                        if (checkRes == "Invalid") checkRes = BAD_SEQ_CODE;
                        // if (searchRes == "Empty") searchRes = "404 Game not checked out by client."
                    }
                    else {
                        checkRes = BAD_SEQ_CODE;
                    }
                    if (sendAll(SSLConnect, checkRes) == -1) {
                        perror("send");
                    }
                }
                else if (heloInit && cmd == "RETURN") {
                    std::string returnRes;
                    if (state == "rent") { // search is only valid in browse
                        returnRes = returnGame(gamesVec, clientCmdVec, clientGames);
                        if (returnRes == "Empty") {
                            returnRes = "404 NOT CHECKED OUT.";
                        }
                    }
                    else {
                        returnRes = BAD_SEQ_CODE;
                    }
                    if (sendAll(SSLConnect, returnRes) == -1) {
                        perror("send");
                    }
                }
                else if (heloInit && cmd == "HISTORY") {
                    std::string historyRes;
                    if (state == "mygames") { // search is only valid in browse
                        historyRes = buildHistoryStr(clientGames, clientRatings);
                        if (historyRes == "Empty") historyRes = "304 NO CONTENT: No rental history found.";
                    }
                    else {
                        historyRes = BAD_SEQ_CODE;
                    }
                    if (sendAll(SSLConnect, historyRes) == -1) {
                        perror("send");
                    }
                }
                else if (heloInit && cmd == "RECOMMEND") {
                    std::string searchRes;
                    if (state == "mygames") { // search is only valid in browse
                        searchRes = buildRecStr(gamesVec, clientGames, clientCmdVec, clientRatings);
                        if (searchRes == "Invalid") searchRes = "503 Bad sequence of commands.";
                    }
                    else {
                        searchRes = BAD_SEQ_CODE;
                    }
                    if (sendAll(SSLConnect, searchRes) == -1) {
                        perror("send");
                    }
                }
                else if (heloInit && cmd == "RATE") { 
                    std::string searchRes;
                    if (state == "mygames") { // search is only valid in browse
                        searchRes = rateGame(clientGames, clientCmdVec, clientRatings);
                        if (searchRes == "Invalid") searchRes = "400 BAD REQUEST: Invalid rating.";
                    }
                    else {
                        searchRes = BAD_SEQ_CODE;
                    }
                    if (sendAll(SSLConnect, searchRes) == -1) {
                        perror("send");
                    }
                }
                else {
                    std::string badReqRes = "400 BAD REQUEST";
                    if (sendAll(SSLConnect, badReqRes.c_str()) == -1) {
                        std::string internalError = "500 INTERNAL SERVER ERROR";
                        // this code is so bad...
                        if (sendAll(SSLConnect, internalError.c_str()) == -1) {
                            perror("send");
                        }
                    }
                }
            }
            
            {
            std::lock_guard<std::mutex> lock(mtx); 

                if (SSLConnect) {
                    std::cout << "freeing SSLConnect" << std::endl;
                  
                    SSL_shutdown(SSLConnect);
                 
                    std::cout << "SSLConnect pointer: " << SSLConnect << std::endl;
                    ERR_print_errors_fp(stderr);
                    SSL_free(SSLConnect);
                    SSLConnect = nullptr;
                    std::cout << "free succeeded" << std::endl;
                }
                else std::cout << "SSLConnect is null" << std::endl;
                close(new_fd);
                return;
            }
        });
        clientThread.detach();
    }
    SSL_CTX_free(context);
    context = nullptr;
    
    return 0;
}