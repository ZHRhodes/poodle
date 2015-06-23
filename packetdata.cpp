#include <string>
#include <iostream>
#include <fstream>

using namespace std;


string spaceClean(string fname);
string dataExtract(string file);


int main(int argc, char* argv[]) {

    string file;

    file = dataExtract(argv[1]);
    cout << file << endl;   
    file = spaceClean(file);
    
    cout << "----------------" << endl
        << file << endl;

    ofstream out("cleanedpackeddata");
    
    out << file;
    out.close();

    return 0;

}

string dataExtract(string fname) {

    string file = "", line;
    ifstream in(fname);
    
    while( getline( in, line)) {
        
        file.append(line.substr(10, 48));

    }
    in.close();
    return file;
}

string spaceClean(string file) {

    string file2 = "";

    for(int i = 0; i < file.length(); ++i) {
        
        if ( ((int) file[i] >= 48 && (int) file[i] <= 57) || ( (int) file[i] >= 97 && (int) file[i] <= 102 ) ) {
            
            file2.push_back(file[i]);
        
        }
        
    }

    return file2;    
}
