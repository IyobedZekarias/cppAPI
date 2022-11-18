#define CROW_ENFORCE_WS_SPEC
#include <crow.h>
#include <crypto_iz.h>
#include <crow/http_request.h>
#include <crow/websocket.h>
#include "base64.h"

using namespace std;
using namespace crow; 
using namespace crypto;

string nniToString(NNI a)
{
    std::stringstream ss;
    ss << a;
    std::string myString = ss.str();
    myString.erase(std::remove(myString.begin(), myString.end(), '\n'), myString.cend());
    return myString; 
}

int main(int argc, char* argv[]) {
    buffer_t a; 
    urand(4, a);
    SimpleApp app;

    CROW_ROUTE(app, "/")
    ([]()
     { return "<div><h1>Hello mom</h1></div>"; });

    CROW_WEBSOCKET_ROUTE(app, "/rsakey")
        .onopen([&](crow::websocket::connection &conn)
                {
    
                    RSAprivate *privg = new RSAprivate;
                    RSApublic *pubg = new RSApublic;
                    generate_rsa(privg, pubg);
                    cout << "done" << endl;

                    stringstream ss, ss2;
                    ss << *privg->d;
                    ss << *privg->p;
                    ss << *privg->q;
                    ss << *privg->d;
                    ss << *privg->phi;

                    ss2 << *pubg->e; 
                    ss2 << *pubg->n;


                    json::wvalue ret;
                    ret["priv"] = base64_encode(ss.str());
                    ret["pub"] = base64_encode(ss2.str());
                    conn.send_text(ret.dump()); })
        .onclose([&](crow::websocket::connection &conn, const std::string &reason)
                 { std::cout << "websocket closed" << endl; })
        .onmessage([&](crow::websocket::connection &conn, const std::string &data, bool is_binary)
                   {
                if (is_binary)
                    std::cout << "data" << endl;
                else
                    conn.send_text("hi back"); });

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
        else if(func == "nni"){
            if(x["op"].s() == "rand"){
                NNI ans;
                NNI::digit_t size;
                json::wvalue ret;
                try
                {
                    size = x["size"].i(); 
                    ans.randnni(size); 
                    ret["ans"] = nniToString(ans); 
                }
                catch (const std::exception &e)
                {
                    ret = {{"Message", "size parameter not set properly"}};
                    return response(403, ret);
                }
                return response(200, ret);
            }
            else if(x["op"].s() == "add"){
                json::wvalue ret;
                try
                {
                    string as = x["a"].s(); 
                    string bs = x["b"].s();
                    NNI a(as.c_str()), b(bs.c_str()), ans; 
                    ans = a + b; 
                    ret["ans"] = nniToString(ans);
                    return response(200, ret);
                }
                catch (const std::exception &e)
                {
                    ret = {{"Message", "a + b parameter not set properly"}};
                    return response(403, ret);
                }
            }
            else if (x["op"].s() == "sub")
            {
                json::wvalue ret;
                try
                {
                    string as = x["a"].s();
                    string bs = x["b"].s();
                    NNI a(as.c_str()), b(bs.c_str()), ans;
                    ans = a - b;
                    ret["ans"] = nniToString(ans);
                    return response(200, ret);
                }
                catch (const std::exception &e)
                {
                    ret = {{"Message", "a - b parameter not set properly"}};
                    return response(403, ret);
                }
            }
            else if (x["op"].s() == "mul")
            {
                json::wvalue ret;
                try
                {
                    string as = x["a"].s();
                    string bs = x["b"].s();
                    NNI a(as.c_str()), b(bs.c_str()), ans;
                    ans = a * b;
                    ret["ans"] = nniToString(ans);
                    return response(200, ret);
                }
                catch (const std::exception &e)
                {
                    ret = {{"Message", "a * b parameter not set properly"}};
                    return response(403, ret);
                }
            }
            else if (x["op"].s() == "div")
            {
                json::wvalue ret;
                try
                {
                    string as = x["a"].s();
                    string bs = x["b"].s();
                    NNI a(as.c_str()), b(bs.c_str()), ans;
                    ans = a / b;
                    ret["ans"] = nniToString(ans);
                    return response(200, ret);
                }
                catch (const std::exception &e)
                {
                    ret = {{"Message", "a / b parameter not set properly"}};
                    return response(403, ret);
                }
            }
            else if (x["op"].s() == "mod")
            {
                json::wvalue ret;
                try
                {
                    string as = x["a"].s();
                    string bs = x["b"].s();
                    NNI a(as.c_str()), b(bs.c_str()), ans;
                    ans = a % b;
                    ret["ans"] = nniToString(ans);
                    return response(200, ret);
                }
                catch (const std::exception &e)
                {
                    ret = {{"Message", "a % b parameter not set properly"}};
                    return response(403, ret);
                }
            }
            else if (x["op"].s() == "modexp")
            {
                json::wvalue ret;
                try
                {
                    string as = x["a"].s();
                    string bs = x["b"].s();
                    string es = x["e"].s();
                    NNI a(as.c_str()), b(bs.c_str()), e(es.c_str()), ans;
                    ans = modexp(a, e, b);
                    ret["ans"] = nniToString(ans);
                    return response(200, ret);
                }
                catch (const std::exception &e)
                {
                    ret = {{"Message", "a^e % b parameter not set properly"}};
                    return response(403, ret);
                }
            }
            else{
                json::wvalue ret = { {"Message", "NNI not formed correctly, op parameter options include"},
                                     {"Options", {{"rand", 1}}} }; 
                return response(403, ret);
            }
        }
        else if(func == "rsa"){
            try
            {            
                // if(x["op"].s() == "key"){
                //     RSAprivate priv; 
                //     RSApublic pub;
                //     generate_rsa(&priv, &pub);

                //     stringstream ss, ss2;
                //     ss << *priv.n;
                //     ss << *priv.p;
                //     ss << *priv.q;
                //     ss << *priv.d;
                //     ss << *priv.phi;

                //     ss2 << *pub.e; 
                //     ss2 << *pub.n;

                //     json::wvalue ret;
                //     ret["priv"] = base64_encode(ss.str());
                //     ret["pub"] = base64_encode(ss2.str());

                //     return response(200, ret);
                // }
                if(x["op"].s() == "encode"){
                    buffer_t message, cipher; 
                    try
                    {
                        string m = x["message"].s(), line;
                        istringstream p(base64_decode(x["pub"].s()));
                        message = buffer_t(m.begin(), m.end()); 
                        RSApublic pub; 
                        getline(p, line);
                        NNI e(line.c_str());
                        pub.e = &e;
                        getline(p, line);
                        NNI n(line.c_str());
                        pub.n = &n;

                        encode_rsa(message, cipher, pub); 
                        json::wvalue ret;
                        ret["cipher"] = base64_encode(string(cipher.begin(), cipher.end()));
                        return response(200, ret); 
                    }
                    catch (const std::exception &e)
                    {
                        json::wvalue eret = {{"Message", "body not formed properly"}};
                        return response(403, eret);
                    }
                }
                else if(x["op"].s() == "decode"){
                    buffer_t message, cipher;
                    try
                    {
                        string c = base64_decode(x["cipher"].s()), line;
                        istringstream p(base64_decode(x["priv"].s()));
                        cipher = buffer_t(c.begin(), c.end());
                        RSAprivate priv;

                        getline(p, line);
                        NNI n(line.c_str()); 
                        priv.n = &n;
                        getline(p, line);
                        NNI p2(line.c_str());
                        priv.p = &p2;
                        getline(p, line);
                        NNI q(line.c_str());
                        priv.q = &q;
                        getline(p, line);
                        NNI d(line.c_str());
                        priv.d = &d;
                        getline(p, line);
                        NNI phi(line.c_str());
                        priv.phi = &phi;

                        decode_rsa(message, cipher, priv);
                        while(message.at(message.size() - 1) == '\0')
                             message.pop_back(); 
                        json::wvalue ret;
                        ret["message"] = string(message.begin(), message.end());
                        return response(200, ret);
                    }
                    catch (const std::exception &e)
                    {
                        json::wvalue eret = {{"Message", "body not formed properly"}};
                        return response(403, eret);
                    }
                }
                else {
                    json::wvalue ret = {{"Message", "op key not correct"}, {"Options", "key, encode, decode"}};
                    return response(403, ret); 
                }
            }
            catch (const std::exception &e)
            {
                json::wvalue ret = {{"Message", "rsa operation needs to be in one of these forms"},
                                    {"Option 1", {{"function", "rsa"}, {"op", "key"}}},
                                    {"Option 2", {{"function", "rsa"}, {"op", "encode"}, {"message", "message to be encoded"}, {"pub", "publc key"}}},
                                    {"Option 3", {{"function", "rsa"}, {"op", "decode"}, {"cipher", "encoded text"}, {"priv", "private key"}}}};
                return response(200, ret);
            }
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
    std::cout << "PORT = " << iPort << "\n";
    std::cout << "hi" << endl;

    app.port(iPort).multithreaded().run(); 

}