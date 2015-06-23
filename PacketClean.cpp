#include <string>
#include <iostream>
#include <fstream>

using namespace std;

int main(int argc, char * argv[]) {


	string fname = argv[1];
	string line = "";

	string file;

	ifstream in(fname);

	while (getline(in, line)) {

		file += line.substr(9,48);

	}


	in.close();

	ofstream out(fname+"clean");

	out << file;
	out.close();

	return 0;



}
