#include <iostream>
#include <vector>

using namespace std;
void func(std::vector<int> v)
{
	v.push_back(5);
}

int main()
{
	std::vector<int> v;
	v.push_back(1);
	v.push_back(2);
	func(v);
	for(auto it = v.begin(); it != v.end(); ++it)
		cout << *it << endl;	
	return 0;
}