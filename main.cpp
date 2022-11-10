#include "crow.h"

using namespace std;
using namespace crow; 

int main(int argc, char* argv[]) {
    SimpleApp app; 

    CROW_ROUTE(app, "/")
    ([]()
     { return "<div><h1>Hello mom</h1></div>"; });

    char * port = getenv("PORT");
    uint16_t iPort = static_cast<uint16_t>(port != NULL? stoi(port): 18080); 
    cout << "PORT = " << iPort << "\n";

    app.bindaddr("67.243.233.3").port(iPort).multithreaded().run();
}