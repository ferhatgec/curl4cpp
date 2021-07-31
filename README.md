# curl4cpp
## single header cURL wrapper for C++ around libcURL.

### An example: 
```cpp
#include <iostream>
#include <string>
#include "curl4.hpp"

int main() {
    curl4::CURL4 init = curl4::easy::init();

    {
        std::string val;

        init.setopt(CURLOPT_URL, "https://raw.githubusercontent.com/ferhatgec/bufsize/master/example.cpp");
        init.setopt(CURLOPT_WRITEFUNCTION, curl4::easy::writefunc);
        init.setopt(CURLOPT_WRITEDATA, &val);
        
        CURLcode res = curl4::easy::perform(init);

        std::cout << val << '\n';
    }

    return 0;
}
```

### curl4cpp licensed under the terms of MIT License.
