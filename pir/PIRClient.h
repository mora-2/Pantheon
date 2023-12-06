#pragma once

class PIRClient
{
private:

    SecretKey secret_key;
    Encryptor encryptor(*context, secret_key);

public:
public:
    PIRClient();
    ~PIRClient();
};