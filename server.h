#pragma once
void EVPDecode(std::vector<unsigned char> &base64Salt, std::tuple<std::array<unsigned char, 16UL>, std::string> &saltAndPass);
