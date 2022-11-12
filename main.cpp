#include <crow.h>
#include <crypto_iz.h>
#include <crow/http_request.h>
#include "base64.h"

using namespace std;
using namespace crow; 
using namespace crypto;

int main(int argc, char* argv[]) {
    buffer_t a; 
    urand(4, a);
    SimpleApp app; 

    CROW_ROUTE(app, "/")
    ([]()
     { return "<div><h1>Hello mom</h1></div>"; });

    CROW_ROUTE(app, "/crypto").methods(HTTPMethod::POST)([](const request &req){ 
        auto x = json::load(req.body);
        string func;
        try
        {
            func = x["function"].s();
        }
        catch(const std::exception& e){
            json::wvalue ret = {{"Message", "function parameter not set in body"}};
            return response(403, ret);
        }

        //FUNCTIONS
        if(func == "aes"){
            if(x["direction"].s() == "encode"){
                string message = x["plain"].s();
                buffer_t key, plain(message.begin(), message.end()), cipher, IV;

                
                try
                {
                    if (base64_decode(x["key"].s()).size() != 16)
                        return response(403, json::wvalue({{"Message", string("Key must be 16 bytes ") + string("not ") + to_string(x["key"].s().size())}}));
                    key = buffer_t(x["key"].s().begin(), x["key"].s().end());
                }
                catch(const std::exception& e)
                {
                    urand(16, key);
                }

                encode_aes128_cbc(plain, key, cipher, IV);
                cipher.insert(cipher.end(), IV.begin(), IV.end());

                json::wvalue ret = json::wvalue(x);
                ret["plain"] = std::string(plain.begin(), plain.end()); 
                ret["key"] = base64_encode(std::string(key.begin(), key.end()));
                ret["cipher"] = base64_encode(std::string(cipher.begin(), cipher.end()));

                return response(ret);
            }
            else if (x["direction"].s() == "decode")
            {
                string cipher_s = base64_decode(x["cipher"].s()), key_s = base64_decode(x["key"].s());
                buffer_t key(key_s.begin(), key_s.end()),
                    plain,
                    cipher(cipher_s.begin(), cipher_s.end()),
                    IV;
                if (key.size() != 16)
                {
                    return response(403, json::wvalue({{"Message", string("Key must be 16 bytes ") + string("not ") + to_string(x["key"].s().size())}}));
                }

                int IVsize = 16;
                for (auto i = cipher.rbegin(); i != cipher.rend(), IVsize > 0; ++i, IVsize--)
                {
                    IV.push_back(*i);
                    cipher.erase((i + 1).base());
                }
                std::reverse(IV.begin(), IV.end());

                decode_aes128_cbc(cipher, key, plain, IV); 

                json::wvalue ret = json::wvalue(x);
                ret["plain"] = std::string(plain.begin(), plain.end());

                return response(ret);
            }
            else
            {
                json::wvalue ret = {{"Message", "AES accepts these values"},
                                    {"plain", "message to be encoded type: string || Optional for decode direction"},
                                    {"cipher", "code to be decoded type: string || Optional for encode direction"},
                                    {"key", "key used to decode | encode type: 16 byte base64 encoded string || Optional for encode direction"},
                                    {"direction", "encode or decode option type: string"}};
                return response(403, ret);
            }
        }
        else if(func == "sha"){
            string message = x["plain"].s();
            buffer_t plain(message.begin(), message.end()), cipher;
            int t = 0;

            try
            {
                if (x["t"].i() > 512 || x["t"].i() < 100)
                    return response(403, json::wvalue({{"Message", "hash level must be between 100 and 512"}}));
            }
            catch (const std::exception &e)
            {
                return response(403, json::wvalue({{"Message", "you must include t in body for hash level 100 to 512"}}));
            }
            try{
                t = x["t"].i();
            } catch(const std::exception &e){
                return response(403, json::wvalue({{"Message", "t must be an integer from 100 to 512"}}));
            }

            hash_sha512(plain, cipher, t); 

            json::wvalue ret = json::wvalue(x);
            ret["hash"] = base64_encode(std::string(cipher.begin(), cipher.end()));

            return response(ret);
        }
        else {
            json::wvalue ret = {{"Message", "function parameter not set to proper option"}, {"Options", 
                                            {{"aes", 1},
                                             {"nni", 1},
                                             {"rand",1},
                                             {"rsa", 1}, 
                                             {"sha", 1} }}};
            return response(403, ret);
        }
    });

    char *port = getenv("PORT");
    uint16_t iPort = static_cast<uint16_t>(port != NULL? stoi(port): 18080); 
    cout << "PORT = " << iPort << "\n";
    cout << "hi" << endl;

    app.port(iPort).multithreaded().run(); 

}