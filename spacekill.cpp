#include <string>
#include <iostream>
#include <fstream>

using namespace std;

int main(int argc, char* argv[]) {

    char c;
    string file = "";
    string fname = argv[1];
    ifstream in(fname);

    while (in >> c) {
        
        if ( ((int) c >= 48 && (int) c <= 57) || ( (int) c >= 97 && (int) c <= 102 )  ) {
            
            file.push_back(c);
        
        }
        
    }

    in.close();
    ofstream out(fname + "cleaned");
    out << file;
    out.close();

    return 0;

}
