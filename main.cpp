#include <crow.h>
#include <crypto_iz.h>

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

    char * port = getenv("PORT");
    uint16_t iPort = static_cast<uint16_t>(port != NULL? stoi(port): 18080); 
    cout << "PORT = " << iPort << "\n"; 

    app.port(iPort).multithreaded().run(); 

}