#include <iostream>
#include <string>
#include "curl4.hpp"

// raw c code taken from 
// https://stackoverflow.com/questions/2329571/c-libcurl-get-output-into-a-string

std::size_t writefunc(void *ptr, std::size_t size, std::size_t nmemb, std::string* s)  {
  s->append(static_cast<char *>(ptr), size*nmemb);
  return size*nmemb;
}

int main() {
    curl4::CURL4 init = curl4::easy::init();

    {
        std::string val;

        curl4::easy::setopt(init, CURLOPT_URL, "https://raw.githubusercontent.com/ferhatgec/bufsize/master/example.cpp");
        curl4::easy::setopt(init, CURLOPT_WRITEFUNCTION, writefunc);
        curl4::easy::setopt(init, CURLOPT_WRITEDATA, &val);

        CURLcode res = curl4::easy::perform(init);

        std::cout << val << '\n';
    }

    return 0;
}
