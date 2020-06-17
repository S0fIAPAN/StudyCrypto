#include <iostream>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/channels.h>
#include <cryptopp/filters.h>

int main()
{
	using namespace CryptoPP;
	
	SHA1 hash;
	
	std::cout<<"Name: "<<hash.AlgorithmName()<<std::endl;
	std::cout<<"Digest size: "<<hash.DigestSize()<<std::endl;
	std::cout<<"Block size: "<<hash.BlockSize()<<std::endl;
	
	std::fstream file("/home/sofa/Workspace/CryptoPP1/file", std::ios::in);
	std::string msg;
	while(!file.eof())
		getline(file, msg);
	
	std::vector<byte> digest(hash.DigestSize());
	
	hash.Update((const byte*)msg.data(), msg.size());
	hash.Final(digest.data());
	
	std::cout<<"Message: "<<msg<<std::endl;
	std::cout<<"Digest: ";
	StringSource(digest.data(), digest.size(), true,
				new HexEncoder(new FileSink(std::cout)));
	std::cout<<std::endl;
	return 0;
}
